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
#include <string.h>
#include "error.h"
#include "utils.h"
#include "repository.h"
#include "oid.h"
#include "tree.h"
#include "diff.h"

extern PyTypeObject TreeType;
extern PyTypeObject TreeEntryType;
extern PyTypeObject DiffType;
extern PyTypeObject TreeIterType;
extern PyTypeObject IndexType;

void
TreeEntry_dealloc(TreeEntry *self)
{
    git_tree_entry_free((git_tree_entry*)self->entry);
    PyObject_Del(self);
}


PyDoc_STRVAR(TreeEntry_filemode__doc__, "Filemode.");

PyObject *
TreeEntry_filemode__get__(TreeEntry *self)
{
    return PyLong_FromLong(git_tree_entry_filemode(self->entry));
}


PyDoc_STRVAR(TreeEntry_name__doc__, "Name.");

PyObject *
TreeEntry_name__get__(TreeEntry *self)
{
    return to_path(git_tree_entry_name(self->entry));
}


PyDoc_STRVAR(TreeEntry_id__doc__, "Object id.");

PyObject *
TreeEntry_id__get__(TreeEntry *self)
{
    const git_oid *oid;

    oid = git_tree_entry_id(self->entry);
    return git_oid_to_python(oid);
}

PyDoc_STRVAR(TreeEntry_oid__doc__, "Object id.\n"
    "This attribute is deprecated. Please use 'id'");

PyObject *
TreeEntry_oid__get__(TreeEntry *self)
{
    return TreeEntry_id__get__(self);
}

PyObject *
TreeEntry_richcompare(PyObject *a, PyObject *b, int op)
{
    PyObject *res;
    int cmp;

    /* We only support comparing to another tree entry */
    if (!PyObject_TypeCheck(b, &TreeEntryType)) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    cmp =git_tree_entry_cmp(((TreeEntry*)a)->entry, ((TreeEntry*)b)->entry);
    switch (op) {
        case Py_LT:
            res = (cmp <= 0) ? Py_True: Py_False;
            break;
        case Py_LE:
            res = (cmp < 0) ? Py_True: Py_False;
            break;
        case Py_EQ:
            res = (cmp == 0) ? Py_True: Py_False;
            break;
        case Py_NE:
            res = (cmp != 0) ? Py_True: Py_False;
            break;
        case Py_GT:
            res = (cmp > 0) ? Py_True: Py_False;
            break;
        case Py_GE:
            res = (cmp >= 0) ? Py_True: Py_False;
            break;
        default:
            PyErr_Format(PyExc_RuntimeError, "Unexpected '%d' op", op);
            return NULL;
    }

    Py_INCREF(res);
    return res;
}


PyDoc_STRVAR(TreeEntry_hex__doc__, "Hex oid.");

PyObject *
TreeEntry_hex__get__(TreeEntry *self)
{
    return git_oid_to_py_str(git_tree_entry_id(self->entry));
}


PyDoc_STRVAR(TreeEntry_type__doc__, "Object type.");

PyObject *
TreeEntry_type__get__(TreeEntry *self)
{
    return PyLong_FromLong(git_tree_entry_type(self->entry));
}


PyGetSetDef TreeEntry_getseters[] = {
    GETTER(TreeEntry, filemode),
    GETTER(TreeEntry, name),
    GETTER(TreeEntry, oid),
    GETTER(TreeEntry, id),
    GETTER(TreeEntry, hex),
    GETTER(TreeEntry, type),
    {NULL}
};


PyDoc_STRVAR(TreeEntry__doc__, "TreeEntry objects.");

PyTypeObject TreeEntryType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_pygit2.TreeEntry",                       /* tp_name           */
    sizeof(TreeEntry),                         /* tp_basicsize      */
    0,                                         /* tp_itemsize       */
    (destructor)TreeEntry_dealloc,             /* tp_dealloc        */
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
    TreeEntry__doc__,                          /* tp_doc            */
    0,                                         /* tp_traverse       */
    0,                                         /* tp_clear          */
    (richcmpfunc)TreeEntry_richcompare,        /* tp_richcompare    */
    0,                                         /* tp_weaklistoffset */
    0,                                         /* tp_iter           */
    0,                                         /* tp_iternext       */
    0,                                         /* tp_methods        */
    0,                                         /* tp_members        */
    TreeEntry_getseters,                       /* tp_getset         */
    0,                                         /* tp_base           */
    0,                                         /* tp_dict           */
    0,                                         /* tp_descr_get      */
    0,                                         /* tp_descr_set      */
    0,                                         /* tp_dictoffset     */
    0,                                         /* tp_init           */
    0,                                         /* tp_alloc          */
    0,                                         /* tp_new            */
};

Py_ssize_t
Tree_len(Tree *self)
{
    assert(self->tree);
    return (Py_ssize_t)git_tree_entrycount(self->tree);
}

int
Tree_contains(Tree *self, PyObject *py_name)
{
    int err;
    git_tree_entry *entry;
    char *name;

    name = py_path_to_c_str(py_name);
    if (name == NULL)
        return -1;

    err = git_tree_entry_bypath(&entry, self->tree, name);
    free(name);

    if (err == GIT_ENOTFOUND)
        return 0;

    if (err < 0) {
        Error_set(err);
        return -1;
    }

    git_tree_entry_free(entry);

    return 1;
}

TreeEntry *
wrap_tree_entry(const git_tree_entry *entry)
{
    TreeEntry *py_entry;

    py_entry = PyObject_New(TreeEntry, &TreeEntryType);
    if (py_entry)
        py_entry->entry = entry;

    return py_entry;
}

int
Tree_fix_index(Tree *self, PyObject *py_index)
{
    long index;
    size_t len;
    long slen;

    index = PyLong_AsLong(py_index);
    if (PyErr_Occurred())
        return -1;

    len = git_tree_entrycount(self->tree);
    slen = (long)len;
    if (index >= slen) {
        PyErr_SetObject(PyExc_IndexError, py_index);
        return -1;
    }
    else if (index < -slen) {
        PyErr_SetObject(PyExc_IndexError, py_index);
        return -1;
    }

    /* This function is called via mp_subscript, which doesn't do negative
     * index rewriting, so we have to do it manually. */
    if (index < 0)
        index = len + index;
    return (int)index;
}

PyObject *
Tree_iter(Tree *self)
{
    TreeIter *iter;

    iter = PyObject_New(TreeIter, &TreeIterType);
    if (iter) {
        Py_INCREF(self);
        iter->owner = self;
        iter->i = 0;
    }
    return (PyObject*)iter;
}

TreeEntry *
Tree_getitem_by_index(Tree *self, PyObject *py_index)
{
    int index;
    const git_tree_entry *entry;
    git_tree_entry *entry_dup;
    int err = 0;

    index = Tree_fix_index(self, py_index);
    if (PyErr_Occurred())
        return NULL;

    entry = git_tree_entry_byindex(self->tree, index);
    if (!entry) {
        PyErr_SetObject(PyExc_IndexError, py_index);
        return NULL;
    }

    err = git_tree_entry_dup(&entry_dup, entry);
    if (err < 0)
        return (TreeEntry*) Error_set(err);

    return wrap_tree_entry(entry_dup);
}

TreeEntry *
Tree_getitem(Tree *self, PyObject *value)
{
    char *path;
    git_tree_entry *entry;
    int err;

    /* Case 1: integer */
    if (PyLong_Check(value))
        return Tree_getitem_by_index(self, value);

    /* Case 2: byte or text string */
    path = py_path_to_c_str(value);
    if (path == NULL)
        return NULL;

    err = git_tree_entry_bypath(&entry, self->tree, path);
    free(path);

    if (err == GIT_ENOTFOUND) {
        PyErr_SetObject(PyExc_KeyError, value);
        return NULL;
    }

    if (err < 0)
        return (TreeEntry*)Error_set(err);

    /* git_tree_entry_dup is already done in git_tree_entry_bypath */
    return wrap_tree_entry(entry);
}


PyDoc_STRVAR(Tree_diff__doc__,
  "diff([obj, flags, empty_tree, context_lines, paths]) -> Diff\n"
  "\n"
  "Get changes between current tree instance with another tree, an index or\n"
  "the working dir.\n"
  "\n"
  "Arguments:\n"
  "\n"
  "obj\n"
  "    If not given compare diff against working dir. Possible valid\n"
  "    arguments are instances of Tree or Index.\n"
  "\n"
  "flags: a GIT_DIFF_* constant.\n"
  "\n"
  "context_lines: the number of unchanged lines that define the boundary\n"
  "   of a hunk (and to display before and after)\n");

PyObject *
Tree_diff(Tree *self, PyObject *args, PyObject *kwds)
{
    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    git_diff *diff;
    git_tree* tree = NULL;
    git_index* index;
    git_repository *repo;
    int err, empty_tree = 0;
    char *keywords[] = {"obj", "flags", "empty_tree", "context_lines", "paths", NULL};

    Diff *py_diff;
    PyObject *py_obj = NULL;
    PyObject *py_paths = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OiiiO", keywords,
                                     &py_obj, &opts.flags, &empty_tree,
                                     &opts.context_lines, &py_paths))
        return NULL;

    err = py_list_to_opts(py_paths, &opts);
    if (err < 0)
        return NULL;

    repo = git_tree_owner(self->tree);
    if (py_obj == NULL) {
        if (empty_tree > 0)
            err = git_diff_tree_to_tree(&diff, repo, self->tree, NULL, &opts);
        else
            err = git_diff_tree_to_workdir(&diff, repo, self->tree, &opts);

    } else if (PyObject_TypeCheck(py_obj, &TreeType)) {
        tree = ((Tree *)py_obj)->tree;
        err = git_diff_tree_to_tree(&diff, repo, self->tree, tree, &opts);

    } else if (PyObject_TypeCheck(py_obj, &IndexType)) {
        index = ((Index *)py_obj)->index;
        err = git_diff_tree_to_index(&diff, repo, self->tree, index, &opts);

    } else {
        free_opts_pathspec(py_paths, &opts);
        PyErr_SetObject(PyExc_TypeError, py_obj);
        return NULL;
    }

    free_opts_pathspec(py_paths, &opts);

    if (err < 0)
        return Error_set(err);

    py_diff = PyObject_New(Diff, &DiffType);
    if (py_diff) {
        Py_INCREF(self->repo);
        py_diff->repo = self->repo;
        py_diff->list = diff;
    }

    return (PyObject*)py_diff;
}


PyDoc_STRVAR(Tree_diff_to_workdir__doc__,
  "diff_to_workdir([flags, context_lines, interhunk_lines, paths]) -> Diff\n"
  "\n"
  "Show the changes between the :py:class:`~pygit2.Tree` and the workdir.\n"
  "\n"
  "Arguments:\n"
  "\n"
  "flags: a GIT_DIFF_* constant.\n"
  "\n"
  "context_lines: the number of unchanged lines that define the boundary\n"
  "   of a hunk (and to display before and after)\n"
  "\n"
  "interhunk_lines: the maximum number of unchanged lines between hunk\n"
  "   boundaries before the hunks will be merged into a one.\n");

PyObject *
Tree_diff_to_workdir(Tree *self, PyObject *args)
{
    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    git_diff *diff;
    Repository *py_repo;
    PyObject *py_paths = NULL;
    int err;

    if (!PyArg_ParseTuple(args, "|IHHO", &opts.flags, &opts.context_lines,
                                        &opts.interhunk_lines, &py_paths))
        return NULL;

    err = py_list_to_opts(py_paths, &opts);
    if (err < 0)
        return NULL;

    py_repo = self->repo;
    err = git_diff_tree_to_workdir(&diff, py_repo->repo, self->tree, &opts);

    free_opts_pathspec(py_paths, &opts);

    if (err < 0)
        return Error_set(err);

    return wrap_diff(diff, py_repo);
}

PyDoc_STRVAR(Tree_diff_to_index__doc__,
  "diff_to_index(index, [flags, context_lines, interhunk_lines, paths]) -> Diff\n"
  "\n"
  "Show the changes between the index and a given :py:class:`~pygit2.Tree`.\n"
  "\n"
  "Arguments:\n"
  "\n"
  "tree: the :py:class:`~pygit2.Tree` to diff.\n"
  "\n"
  "flags: a GIT_DIFF_* constant.\n"
  "\n"
  "context_lines: the number of unchanged lines that define the boundary\n"
  "   of a hunk (and to display before and after)\n"
  "\n"
  "interhunk_lines: the maximum number of unchanged lines between hunk\n"
  "   boundaries before the hunks will be merged into a one.\n");

PyObject *
Tree_diff_to_index(Tree *self, PyObject *args, PyObject *kwds)
{
    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    git_diff *diff;
    Repository *py_repo;
    PyObject *py_paths = NULL;
    int err;

    Index *py_idx = NULL;

    if (!PyArg_ParseTuple(args, "O!|IHHO", &IndexType, &py_idx, &opts.flags,
                                        &opts.context_lines,
                                        &opts.interhunk_lines,
                                        &py_paths))
        return NULL;

    err = py_list_to_opts(py_paths, &opts);
    if (err < 0)
        return NULL;

    py_repo = self->repo;
    err = git_diff_tree_to_index(&diff, py_repo->repo, self->tree,
                                 py_idx->index, &opts);

    free_opts_pathspec(py_paths, &opts);

    if (err < 0)
        return Error_set(err);

    return wrap_diff(diff, py_repo);
}


PyDoc_STRVAR(Tree_diff_to_tree__doc__,
  "diff_to_tree([tree, flags, context_lines, interhunk_lines, swap, paths]) -> Diff\n"
  "\n"
  "Show the changes between two trees\n"
  "\n"
  "Arguments:\n"
  "\n"
  "tree: the :py:class:`~pygit2.Tree` to diff. If no tree is given the empty\n"
  "   tree will be used instead.\n"
  "\n"
  "flag: a GIT_DIFF_* constant.\n"
  "\n"
  "context_lines: the number of unchanged lines that define the boundary\n"
  "   of a hunk (and to display before and after)\n"
  "\n"
  "interhunk_lines: the maximum number of unchanged lines between hunk\n"
  "   boundaries before the hunks will be merged into a one.\n"
  "\n"
  "swap: instead of diffing a to b. Diff b to a.\n");

PyObject *
Tree_diff_to_tree(Tree *self, PyObject *args, PyObject *kwds)
{
    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    git_diff *diff;
    git_tree *from, *to, *tmp;
    Repository *py_repo;
    int err, swap = 0;
    char *keywords[] = {"obj", "flags", "context_lines", "interhunk_lines",
                        "swap", "paths", NULL};
    PyObject *py_paths = NULL;

    Tree *py_tree = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!IHHiO", keywords,
                                     &TreeType, &py_tree, &opts.flags,
                                     &opts.context_lines,
                                     &opts.interhunk_lines, &swap,
                                     &py_paths))
        return NULL;

    err = py_list_to_opts(py_paths, &opts);
    if (err < 0)
        return NULL;

    py_repo = self->repo;
    to = (py_tree == NULL) ? NULL : py_tree->tree;
    from = self->tree;
    if (swap > 0) {
        tmp = from;
        from = to;
        to = tmp;
    }

    err = git_diff_tree_to_tree(&diff, py_repo->repo, from, to, &opts);

    free_opts_pathspec(py_paths, &opts);

    if (err < 0)
        return Error_set(err);

    return wrap_diff(diff, py_repo);
}


PyDoc_STRVAR(Tree_merge__doc__,
  "merge([base_tree, others_tree]) -> Index\n"
  "Merges two trees and returns the Index object that reflects the result of the merge\n");

PyObject *
Tree_merge(Tree *self, PyObject *args, PyObject *kwds)
{
    git_index *merge_index;
    Repository *py_repo;
    Tree *py_others;
    Tree *py_base;
    git_merge_options opts = GIT_MERGE_OPTIONS_INIT;
    Index *py_merge_index;
    int err;
    if (!PyArg_ParseTuple(args, "O!O!", &TreeType, &py_others,
                                        &TreeType, &py_base))
        return NULL;

    py_repo = self->repo;
    err = git_merge_trees(&merge_index, py_repo->repo, py_base->tree,
                            self->tree, py_others->tree, &opts);
    if (err < 0)
        return Error_set(err);

    py_merge_index = PyObject_GC_New(Index, &IndexType);
    if (!py_merge_index) {
        git_index_free(merge_index);
        return NULL;
    }

    Py_INCREF(py_repo);
    py_merge_index->repo = py_repo;
    py_merge_index->index = merge_index;
    PyObject_GC_Track(py_merge_index);
    return (PyObject *) py_merge_index;

}


PySequenceMethods Tree_as_sequence = {
    0,                          /* sq_length */
    0,                          /* sq_concat */
    0,                          /* sq_repeat */
    0,                          /* sq_item */
    0,                          /* sq_slice */
    0,                          /* sq_ass_item */
    0,                          /* sq_ass_slice */
    (objobjproc)Tree_contains,  /* sq_contains */
};

PyMappingMethods Tree_as_mapping = {
    (lenfunc)Tree_len,            /* mp_length */
    (binaryfunc)Tree_getitem,     /* mp_subscript */
    0,                            /* mp_ass_subscript */
};

PyMethodDef Tree_methods[] = {
    METHOD(Tree, diff, METH_VARARGS | METH_KEYWORDS), /* compatibility */
    METHOD(Tree, diff_to_tree, METH_VARARGS | METH_KEYWORDS),
    METHOD(Tree, diff_to_workdir, METH_VARARGS),
    METHOD(Tree, diff_to_index, METH_VARARGS | METH_KEYWORDS),
    METHOD(Tree, merge, METH_VARARGS),
    {NULL}
};


PyDoc_STRVAR(Tree__doc__, "Tree objects.");

PyTypeObject TreeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_pygit2.Tree",                            /* tp_name           */
    sizeof(Tree),                              /* tp_basicsize      */
    0,                                         /* tp_itemsize       */
    0,                                         /* tp_dealloc        */
    0,                                         /* tp_print          */
    0,                                         /* tp_getattr        */
    0,                                         /* tp_setattr        */
    0,                                         /* tp_compare        */
    0,                                         /* tp_repr           */
    0,                                         /* tp_as_number      */
    &Tree_as_sequence,                         /* tp_as_sequence    */
    &Tree_as_mapping,                          /* tp_as_mapping     */
    0,                                         /* tp_hash           */
    0,                                         /* tp_call           */
    0,                                         /* tp_str            */
    0,                                         /* tp_getattro       */
    0,                                         /* tp_setattro       */
    0,                                         /* tp_as_buffer      */
    Py_TPFLAGS_DEFAULT,                        /* tp_flags          */
    Tree__doc__,                               /* tp_doc            */
    0,                                         /* tp_traverse       */
    0,                                         /* tp_clear          */
    0,                                         /* tp_richcompare    */
    0,                                         /* tp_weaklistoffset */
    (getiterfunc)Tree_iter,                    /* tp_iter           */
    0,                                         /* tp_iternext       */
    Tree_methods,                              /* tp_methods        */
    0,                                         /* tp_members        */
    0,                                         /* tp_getset         */
    0,                                         /* tp_base           */
    0,                                         /* tp_dict           */
    0,                                         /* tp_descr_get      */
    0,                                         /* tp_descr_set      */
    0,                                         /* tp_dictoffset     */
    0,                                         /* tp_init           */
    0,                                         /* tp_alloc          */
    0,                                         /* tp_new            */
};


void
TreeIter_dealloc(TreeIter *self)
{
    Py_CLEAR(self->owner);
    PyObject_Del(self);
}

TreeEntry *
TreeIter_iternext(TreeIter *self)
{
    const git_tree_entry *entry;
    git_tree_entry *entry_dup;
    int err = 0;

    entry = git_tree_entry_byindex(self->owner->tree, self->i);
    if (!entry)
        return NULL;

    self->i += 1;

    err = git_tree_entry_dup(&entry_dup, entry);
    if (err < 0)
        return (TreeEntry*) Error_set(err);

    return wrap_tree_entry(entry_dup);
}


PyDoc_STRVAR(TreeIter__doc__, "Tree iterator.");

PyTypeObject TreeIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_pygit2.TreeIter",                        /* tp_name           */
    sizeof(TreeIter),                          /* tp_basicsize      */
    0,                                         /* tp_itemsize       */
    (destructor)TreeIter_dealloc ,             /* tp_dealloc        */
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
    TreeIter__doc__,                           /* tp_doc            */
    0,                                         /* tp_traverse       */
    0,                                         /* tp_clear          */
    0,                                         /* tp_richcompare    */
    0,                                         /* tp_weaklistoffset */
    PyObject_SelfIter,                         /* tp_iter           */
    (iternextfunc)TreeIter_iternext,           /* tp_iternext       */
};
