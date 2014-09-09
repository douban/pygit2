/*
 * Copyright 2010-2014 The pygit2 contributors
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * In addition to the permissions in the GNU General Public License,
 * the authors give you unlimited permission to link the compiled
 * version of this file into combinations with other programs,
 * and to distribute those combinations without any restriction
 * coming from the use of this file.  (The General Public License
 * restrictions do apply in other respects; for example, they cover
 * modification of the file, and distribution when not linked into
 * a combined executable.)
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "error.h"
#include "utils.h"
#include "signature.h"
#include "commit.h"
#include "object.h"
#include "pthread.h"
#include "oid.h"

extern PyTypeObject TreeType;

int
compare_delta_path(const git_diff_delta *delta, git_diff_options *opts)
{
    unsigned int i;
    int res = -1;
    int cmp;
    int length = opts->pathspec.count;
    char **paths = opts->pathspec.strings;
    for (i = 0; i < length; i++) {
        cmp = strncmp(delta->old_file.path, paths[i], strlen(paths[i]));
        if (cmp != 0)
            continue;
        res = i;
        break;
    }
    return res;
}

int
diff_path_bytree(git_diff *diff, git_diff_options *opts, int *indexs)
{
    git_patch* patch = NULL;
    const git_diff_delta *delta;
    unsigned int i;
    int ndeltas;
    int index;
    int count = 0;
    ndeltas = (int)git_diff_num_deltas(diff);
    for (i = 0; i < ndeltas; i++) {
        delta = git_diff_get_delta(diff, i);
        if (delta == NULL)
            continue;
        index = compare_delta_path(delta, opts);
        if (index < 0)
            continue;
        indexs[index] ++;
        count ++;
    }
    return count;
}

int
diff_tree_byparent(git_repository *repo, git_commit *commit, unsigned int index,
        git_diff_options *opts, git_diff **diff)
{
    const git_oid *parent_oid;
    git_commit *parent;
    git_tree* parent_tree = NULL;
    git_tree* tree = NULL;
    int err;
    parent_oid = git_commit_parent_id(commit, index);
    if (parent_oid == NULL) {
        err = GIT_ENOTFOUND;
        goto cleanup;
    }

    err = git_commit_lookup(&parent, repo, parent_oid);
    if (err < 0)
        goto cleanup;

    err = git_commit_tree(&parent_tree, parent);
    if (err < 0)
        goto cleanup_ptree;

    err = git_commit_tree(&tree, commit);
    if (err < 0)
        goto cleanup_tree;

    err = git_diff_tree_to_tree(diff, repo, parent_tree, tree, opts);
    if (err < 0)
        goto cleanup_diff;

cleanup_diff:
    git_tree_free(tree);
cleanup_tree:
    git_tree_free(parent_tree);
cleanup_ptree:
    git_commit_free(parent);
cleanup:
    return err;
}

int
diff_tree(git_repository *repo, git_commit *commit,
        git_diff_options *opts, git_diff **diff)
{
    git_tree* tree = NULL;
    int err;

    err = git_commit_tree(&tree, commit);
    if (err < 0)
        goto cleanup_tree;

    err = git_diff_tree_to_tree(diff, repo, NULL, tree, opts);
    if (err < 0)
        goto cleanup_diff;

cleanup_diff:
    git_tree_free(tree);
cleanup_tree:
    return err;
}

struct diff_thread_t
{
    int id;
    pthread_t thread;
    git_tree *tree;
    git_tree *parent_tree;
    char *path;
    int *indexs;
};

typedef struct diff_thread_t diff_thread_t;

void
diff_path_byentry_func(void *arg)
{
    git_tree *tree;
    git_tree *parent_tree;
    char *path;
    const git_tree_entry *entry;
    const git_tree_entry *parent_entry;
    diff_thread_t *thread = (diff_thread_t *)arg;
    tree = thread->tree;
    parent_tree = thread->parent_tree;
    path = thread->path;
    int err;
    int re;

    err = git_tree_entry_bypath((git_tree_entry **)&entry, tree, path);
    if (err < 0) {
        if (err != GIT_ENOTFOUND)
            goto cleanup;
        entry = NULL;
    }
    if (parent_tree == NULL) {
        if (entry == NULL)
            goto cleanup;
        git_tree_entry_free((git_tree_entry *)entry);
    } else {
        err = git_tree_entry_bypath((git_tree_entry **)&parent_entry, parent_tree, path);
        if (err < 0) {
            if (err != GIT_ENOTFOUND)
                goto cleanup_error;
            parent_entry = NULL;
        }
        if (entry == NULL && parent_entry == NULL)
            goto cleanup;
        if (entry != NULL && parent_entry != NULL) {
            re = memcmp(git_tree_entry_id(entry)->id, git_tree_entry_id(parent_entry)->id,
                    GIT_OID_RAWSZ);
            if (re == 0) {
                git_tree_entry_free((git_tree_entry *)parent_entry);
                git_tree_entry_free((git_tree_entry *)entry);
                goto cleanup;
            }
        }
        if (entry != NULL)
            git_tree_entry_free((git_tree_entry *)entry);
        if (parent_entry != NULL)
            git_tree_entry_free((git_tree_entry *)parent_entry);
    }
    thread->indexs[thread->id] ++;
    pthread_exit(0);
cleanup_error:
    git_tree_entry_free((git_tree_entry *)entry);
cleanup:
    pthread_exit(0);
}

int
diff_path_byentry_threaded(git_tree *tree, git_tree *parent_tree,
        git_diff_options *opts, int *indexs)
{
    int length = opts->pathspec.count;
    char **paths = opts->pathspec.strings;
    int i;
    int err;
    diff_thread_t *threads;
    diff_thread_t *thread;
    threads = (diff_thread_t *)calloc(length, sizeof (diff_thread_t));
    for (i = 0; i < length; i++) {
        thread = &threads[i];
        thread->id = i;
        thread->tree = tree;
        thread->parent_tree = parent_tree;
        thread->path = paths[i];
        thread->indexs = indexs;
        err = pthread_create(&thread->thread, NULL, (void *) &diff_path_byentry_func, (void *) thread);
    }
    for (i = 0; i < length; i++) {
        thread = &threads[i];
        err = pthread_join(thread->thread, NULL);
    }
    free(threads);
    return 0;
}

int
diff_path_byentry(git_tree *tree, git_tree *parent_tree,
        git_diff_options *opts, int *indexs)
{
    const git_tree_entry *entry;
    const git_tree_entry *parent_entry;
    int length = opts->pathspec.count;
    char **paths = opts->pathspec.strings;
    int i;
    int err;
    int re;
    for (i = 0; i < length; i++) {
        if (indexs[i] > 0)
            continue;
        err = git_tree_entry_bypath((git_tree_entry **)&entry, tree, paths[i]);
        if (err < 0) {
            if (err != GIT_ENOTFOUND)
                goto cleanup;
            entry = NULL;
        }
        if (parent_tree == NULL) {
            if (entry == NULL)
                continue;
            git_tree_entry_free((git_tree_entry *)entry);
        } else {
            err = git_tree_entry_bypath((git_tree_entry **)&parent_entry, parent_tree, paths[i]);
            if (err < 0) {
                if (err != GIT_ENOTFOUND)
                    goto cleanup_error;
                parent_entry = NULL;
            }
            if (entry == NULL && parent_entry == NULL)
                continue;
            if (entry != NULL && parent_entry != NULL) {
                re = memcmp(git_tree_entry_id(entry)->id, git_tree_entry_id(parent_entry)->id,
                        GIT_OID_RAWSZ);
                if (re == 0) {
                    git_tree_entry_free((git_tree_entry *)parent_entry);
                    git_tree_entry_free((git_tree_entry *)entry);
                    continue;
                }
            }
            if (entry != NULL)
                git_tree_entry_free((git_tree_entry *)entry);
            if (parent_entry != NULL)
                git_tree_entry_free((git_tree_entry *)parent_entry);
        }
        indexs[i] ++;
    }
    return 0;

cleanup_error:
    git_tree_entry_free((git_tree_entry *)entry);
cleanup:
    return err;
}

int
diff_entry(git_repository *repo, git_commit *commit,
        git_diff_options *opts, int *indexs)
{
    git_tree* tree = NULL;
    int err;
    err = git_commit_tree(&tree, commit);
    if (err < 0)
        goto cleanup;

    err = diff_path_byentry(tree, NULL, opts, indexs);

cleanup_entry:
    git_tree_free(tree);
cleanup:
    return err;
}

int
diff_entry_byparent(git_repository *repo, git_commit *commit, unsigned int index,
        git_diff_options *opts, int *indexs)
{
    const git_oid *parent_oid;
    git_commit *parent;
    git_tree* parent_tree = NULL;
    git_tree* tree = NULL;
    int err;
    int count;
    parent_oid = git_commit_parent_id(commit, index);
    if (parent_oid == NULL) {
        err = GIT_ENOTFOUND;
        goto cleanup;
    }

    err = git_commit_lookup(&parent, repo, parent_oid);
    if (err < 0)
        goto cleanup;

    err = git_commit_tree(&parent_tree, parent);
    if (err < 0)
        goto cleanup_ptree;

    err = git_commit_tree(&tree, commit);
    if (err < 0)
        goto cleanup_tree;

    err = diff_path_byentry(tree, parent_tree, opts, indexs);

cleanup_entry:
    git_tree_free(tree);
cleanup_tree:
    git_tree_free(parent_tree);
cleanup_ptree:
    git_commit_free(parent);
cleanup:
    return err;
}

int
diff_entry_threaded(git_repository *repo, git_commit *commit,
        git_diff_options *opts, int *indexs)
{
    git_tree* tree = NULL;
    int err;
    err = git_commit_tree(&tree, commit);
    if (err < 0)
        goto cleanup;

    err = diff_path_byentry_threaded(tree, NULL, opts, indexs);

cleanup_entry:
    git_tree_free(tree);
cleanup:
    return err;
}

int
diff_entry_byparent_threaded(git_repository *repo, git_commit *commit, unsigned int index,
        git_diff_options *opts, int *indexs)
{
    const git_oid *parent_oid;
    git_commit *parent;
    git_tree* parent_tree = NULL;
    git_tree* tree = NULL;
    int err;
    int count;
    parent_oid = git_commit_parent_id(commit, index);
    if (parent_oid == NULL) {
        err = GIT_ENOTFOUND;
        goto cleanup;
    }

    err = git_commit_lookup(&parent, repo, parent_oid);
    if (err < 0)
        goto cleanup;

    err = git_commit_tree(&parent_tree, parent);
    if (err < 0)
        goto cleanup_ptree;

    err = git_commit_tree(&tree, commit);
    if (err < 0)
        goto cleanup_tree;

    err = diff_path_byentry_threaded(tree, parent_tree, opts, indexs);

cleanup_entry:
    git_tree_free(tree);
cleanup_tree:
    git_tree_free(parent_tree);
cleanup_ptree:
    git_commit_free(parent);
cleanup:
    return err;
}


PyDoc_STRVAR(Commit_message_encoding__doc__, "Message encoding.");

PyObject *
Commit_message_encoding__get__(Commit *commit)
{
    const char *encoding;

    encoding = git_commit_message_encoding(commit->commit);
    if (encoding == NULL)
        Py_RETURN_NONE;

    return to_encoding(encoding);
}


PyDoc_STRVAR(Commit_message__doc__, "The commit message, a text string.");

PyObject *
Commit_message__get__(Commit *commit)
{
    const char *message, *encoding;

    message = git_commit_message(commit->commit);
    encoding = git_commit_message_encoding(commit->commit);
    return to_unicode(message, encoding, "strict");
}


PyDoc_STRVAR(Commit_raw_message__doc__, "Message (bytes).");

PyObject *
Commit_raw_message__get__(Commit *commit)
{
    return PyBytes_FromString(git_commit_message(commit->commit));
}


PyDoc_STRVAR(Commit_commit_time__doc__, "Commit time.");

PyObject *
Commit_commit_time__get__(Commit *commit)
{
    return PyLong_FromLongLong(git_commit_time(commit->commit));
}


PyDoc_STRVAR(Commit_commit_time_offset__doc__, "Commit time offset.");

PyObject *
Commit_commit_time_offset__get__(Commit *commit)
{
    return PyLong_FromLong(git_commit_time_offset(commit->commit));
}


PyDoc_STRVAR(Commit_committer__doc__, "The committer of the commit.");

PyObject *
Commit_committer__get__(Commit *self)
{
    const git_signature *signature;
    const char *encoding;

    signature = git_commit_committer(self->commit);
    encoding = git_commit_message_encoding(self->commit);

    return build_signature((Object*)self, signature, encoding);
}


PyDoc_STRVAR(Commit_author__doc__, "The author of the commit.");

PyObject *
Commit_author__get__(Commit *self)
{
    const git_signature *signature;
    const char *encoding;

    signature = git_commit_author(self->commit);
    encoding = git_commit_message_encoding(self->commit);

    return build_signature((Object*)self, signature, encoding);
}

PyDoc_STRVAR(Commit_tree__doc__, "The tree object attached to the commit.");

PyObject *
Commit_tree__get__(Commit *commit)
{
    git_tree *tree;
    Tree *py_tree;
    int err;

    err = git_commit_tree(&tree, commit->commit);
    if (err == GIT_ENOTFOUND)
        Py_RETURN_NONE;

    if (err < 0)
        return Error_set(err);

    py_tree = PyObject_New(Tree, &TreeType);
    if (py_tree) {
        Py_INCREF(commit->repo);
        py_tree->repo = commit->repo;
        py_tree->tree = (git_tree*)tree;
    }
    return (PyObject*)py_tree;
}

PyDoc_STRVAR(Commit_tree_id__doc__, "The id of the tree attached to the commit.");

PyObject *
Commit_tree_id__get__(Commit *commit)
{
    return git_oid_to_python(git_commit_tree_id(commit->commit));
}

PyDoc_STRVAR(Commit_parents__doc__, "The list of parent commits.");

PyObject *
Commit_parents__get__(Commit *self)
{
    Repository *py_repo;
    unsigned int i, parent_count;
    const git_oid *parent_oid;
    git_commit *parent;
    int err;
    PyObject *py_parent;
    PyObject *list;

    parent_count = git_commit_parentcount(self->commit);
    list = PyList_New(parent_count);
    if (!list)
        return NULL;

    py_repo = self->repo;
    for (i=0; i < parent_count; i++) {
        parent_oid = git_commit_parent_id(self->commit, i);
        if (parent_oid == NULL) {
            Py_DECREF(list);
            Error_set(GIT_ENOTFOUND);
            return NULL;
        }

        err = git_commit_lookup(&parent, py_repo->repo, parent_oid);
        if (err < 0) {
            Py_DECREF(list);
            return Error_set_oid(err, parent_oid, GIT_OID_HEXSZ);
        }

        py_parent = wrap_object((git_object*)parent, py_repo);
        if (py_parent == NULL) {
            Py_DECREF(list);
            return NULL;
        }

        PyList_SET_ITEM(list, i, py_parent);
    }

    return list;
}

PyDoc_STRVAR(Commit_parent_ids__doc__, "The list of parent commits' ids.");

PyObject *
Commit_parent_ids__get__(Commit *self)
{
    unsigned int i, parent_count;
    const git_oid *id;
    PyObject *list;

    parent_count = git_commit_parentcount(self->commit);
    list = PyList_New(parent_count);
    if (!list)
        return NULL;

    for (i=0; i < parent_count; i++) {
        id = git_commit_parent_id(self->commit, i);
        PyList_SET_ITEM(list, i, git_oid_to_python(id));
    }

    return list;
}

PyGetSetDef Commit_getseters[] = {
    GETTER(Commit, message_encoding),
    GETTER(Commit, message),
    GETTER(Commit, raw_message),
    GETTER(Commit, commit_time),
    GETTER(Commit, commit_time_offset),
    GETTER(Commit, committer),
    GETTER(Commit, author),
    GETTER(Commit, tree),
    GETTER(Commit, tree_id),
    GETTER(Commit, parents),
    GETTER(Commit, parent_ids),
    {NULL}
};


PyDoc_STRVAR(Commit_is_changed__doc__,
  "is_changed(paths, [flags, no_merges]) -> Diff\n"
  "\n"
  "check the paths are changed in current commit\n"
  "\n"
  "Arguments:\n"
  "\n"
  "paths: file path list.\n"
  "\n"
  "no_merges: boolean, escape merge commit or not.\n"
  "\n"
  "flags: a GIT_DIFF_* constant.\n"
  "\n");

PyObject *
Commit_is_changed(Commit *self, PyObject *args, PyObject *kwds)
{
    const git_oid *parent_oid;
    git_commit *parent;
    git_tree* tree = NULL;
    git_tree* parent_tree = NULL;
    git_diff *diff;
    git_repository *repo;
    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    unsigned int i;
    unsigned int parent_count;
    int err;
    int ndeltas;
    char *keywords[] = {"paths", "flags", "no_merges", "no_diff", "thread", NULL};
    Repository *py_repo;
    PyObject *py_paths = NULL;
    PyObject *py_diff_paths = NULL;
    PyObject *py_no_merges = NULL;
    PyObject *py_no_diff = NULL;
    PyObject *py_thread = NULL;
    int *path_indexs;


    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|iOOO", keywords,
                                     &py_paths, &opts.flags, &py_no_merges,
                                     &py_no_diff, &py_thread))
        return NULL;

    if (!PyObject_TypeCheck(py_paths, &PyList_Type)) {
        PyErr_SetObject(PyExc_TypeError, py_paths);
        return NULL;
    }

    if (py_no_merges != NULL &&
            (py_no_merges != Py_None &&
             !PyObject_TypeCheck(py_no_merges, &PyBool_Type))
       ) {
        PyErr_SetObject(PyExc_TypeError, py_no_merges);
        return NULL;
    }

    if (py_no_diff != NULL &&
            (py_no_diff != Py_None &&
             !PyObject_TypeCheck(py_no_diff, &PyBool_Type))
       ) {
        PyErr_SetObject(PyExc_TypeError, py_no_diff);
        return NULL;
    }

    int paths_length = 0;
    PyObject *py_path = NULL;
    paths_length = PyList_Size(py_paths);
    if (paths_length <= 0) {
        PyErr_SetObject(PyExc_ValueError, py_paths);
        return NULL;
    }
    for (i = 0; i < paths_length; i++) {
        py_path = PyList_GetItem(py_paths, i);
        if (!PyObject_TypeCheck(py_path, &PyString_Type)) {
            PyErr_SetObject(PyExc_TypeError, py_path);
            return NULL;
        }
    }
    opts.pathspec.count = paths_length;
    opts.pathspec.strings = (char **) PyMem_Malloc(paths_length * sizeof (char *));
    path_indexs = (int *)PyMem_Malloc(paths_length * sizeof (int));
    for (i = 0; i < paths_length; i++) {
        py_path = PyList_GetItem(py_paths, i);
        opts.pathspec.strings[i] = PyString_AsString(py_path);
        path_indexs[i] = 0;
    }

    py_repo = self->repo;
    repo = py_repo->repo;
    parent_count = git_commit_parentcount(self->commit);
    if (py_no_merges != NULL &&
            py_no_merges != Py_None && PyObject_IsTrue(py_no_merges)) {
        if (parent_count > 1)
            goto cleanup_empty;
    }

    if (py_thread != NULL &&
            py_thread != Py_None && PyObject_IsTrue(py_thread)) {
        if (parent_count > 0) {
            for (i = 0; i < parent_count; i++) {
                err = diff_entry_byparent_threaded(repo, self->commit, i, &opts, path_indexs);
                if (err < 0)
                    goto cleanup_error;
            }
        } else {
            err = diff_entry_threaded(repo, self->commit, &opts, path_indexs);
            if (err < 0)
                goto cleanup_error;
        }
        goto cleanup_empty;
    }

    if (py_no_diff != NULL &&
            py_no_diff != Py_None && PyObject_IsTrue(py_no_diff)) {
        if (parent_count > 0) {
            for (i = 0; i < parent_count; i++) {
                err = diff_entry_byparent(repo, self->commit, i, &opts, path_indexs);
                if (err < 0)
                    goto cleanup_error;
            }
        } else {
            err = diff_entry(repo, self->commit, &opts, path_indexs);
            if (err < 0)
                goto cleanup_error;
        }
        goto cleanup_empty;
    }

    if (parent_count > 0) {
        for (i = 0; i < parent_count; i++) {
            err = diff_tree_byparent(repo, self->commit, i, &opts, &diff);
            if (err < 0)
                goto cleanup_error;
            err = diff_path_bytree(diff, &opts, path_indexs);
            git_diff_free(diff);
            if (err < 0)
                goto cleanup_error;
        }
    } else {
        err = diff_tree(repo, self->commit, &opts, &diff);
        if (err < 0)
            goto cleanup_error;
        err = diff_path_bytree(diff, &opts, path_indexs);
        git_diff_free(diff);
        if (err < 0)
            goto cleanup_error;
    }

cleanup_empty:
    py_diff_paths = PyList_New(paths_length);
    for (i = 0; i < paths_length; i++) {
        PyList_SetItem(py_diff_paths, i, Py_BuildValue("i", path_indexs[i]));
    }

cleanup:
    PyMem_Free(opts.pathspec.strings);
    PyMem_Free(path_indexs);
    return py_diff_paths;

cleanup_error:
    PyMem_Free(opts.pathspec.strings);
    PyMem_Free(path_indexs);
    return NULL;
}

PyMethodDef Commit_methods[] = {
    METHOD(Commit, is_changed, METH_VARARGS|METH_KEYWORDS),
    {NULL}
};

PyDoc_STRVAR(Commit__doc__, "Commit objects.");

PyTypeObject CommitType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_pygit2.Commit",                          /* tp_name           */
    sizeof(Commit),                            /* tp_basicsize      */
    0,                                         /* tp_itemsize       */
    0,                                         /* tp_dealloc        */
    0,                                         /* tp_print          */
    0,                                         /* tp_getattr        */
    0,                                         /* tp_setattr        */
    0,                                         /* tp_compare        */
    0,                                         /* tp_repr           */
    0,                                         /* tp_as_number      */
    0,                                         /* tp_as_sequence    */
    0,                                         /* tp_as_mapping     */
    0,                                         /* tp_hash           */
    0,                                         /* tp_call           */
    0,                                         /* tp_str            */
    0,                                         /* tp_getattro       */
    0,                                         /* tp_setattro       */
    0,                                         /* tp_as_buffer      */
    Py_TPFLAGS_DEFAULT,                        /* tp_flags          */
    Commit__doc__,                             /* tp_doc            */
    0,                                         /* tp_traverse       */
    0,                                         /* tp_clear          */
    0,                                         /* tp_richcompare    */
    0,                                         /* tp_weaklistoffset */
    0,                                         /* tp_iter           */
    0,                                         /* tp_iternext       */
    Commit_methods,                            /* tp_methods        */
    0,                                         /* tp_members        */
    Commit_getseters,                          /* tp_getset         */
    0,                                         /* tp_base           */
    0,                                         /* tp_dict           */
    0,                                         /* tp_descr_get      */
    0,                                         /* tp_descr_set      */
    0,                                         /* tp_dictoffset     */
    0,                                         /* tp_init           */
    0,                                         /* tp_alloc          */
    0,                                         /* tp_new            */
};
