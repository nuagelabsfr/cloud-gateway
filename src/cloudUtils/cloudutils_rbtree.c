/*
 * This file is part of Nuage Labs SAS's Cloud Gateway.
 *
 * Copyright (C) 2011-2017  Nuage Labs SAS
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/* The authors of this work have released all rights to it and placed it
in the public domain under the Creative Commons CC0 1.0 waiver
(http://creativecommons.org/publicdomain/zero/1.0/).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Retrieved from: http://en.literateprograms.org/Red-black_tree_(C)?oldid=19567
*/

#include <errno.h>

#include <cloudutils/cloudutils.h>
#include <cloudutils/cloudutils_rbtree.h>

typedef enum
{
    cgutils_rbtree_color_black = 0,
    cgutils_rbtree_color_red = 1,
} cgutils_rbtree_color;

struct cgutils_rbtree_node
{
    cgutils_rbtree_node * parent;
    cgutils_rbtree_node * left;
    cgutils_rbtree_node * right;

    void * key;
    void * value;

    cgutils_rbtree_color color;
};

struct cgutils_rbtree
{
    cgutils_rbtree_compare * compare;
    cgutils_rbtree_key_delete * key_del;
    cgutils_rbtree_value_delete * value_del;
    cgutils_rbtree_node * root;
};

static void cgutils_rbtree_node_free(cgutils_rbtree const * const tree,
                                     cgutils_rbtree_node * node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    if (tree->key_del != NULL)
    {
        (*(tree->key_del))(node->key);
    }
    node->key = NULL;

    if (tree->value_del != NULL)
    {
        (*(tree->value_del))(node->value);
    }
    node->value = NULL;

    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;
    CGUTILS_FREE(node);
}

static cgutils_rbtree_color cgutils_rbtree_node_color(cgutils_rbtree_node const * const node)
{
    return node != NULL ? node->color : cgutils_rbtree_color_black;
}

static cgutils_rbtree_node * cgutils_rbtree_grandparent(cgutils_rbtree_node const * const node)
{
    CGUTILS_ASSERT(node != NULL);
    CGUTILS_ASSERT(node->parent != NULL);
    CGUTILS_ASSERT(node->parent->parent != NULL);

    return node->parent->parent;
}

static cgutils_rbtree_node * cgutils_rbtree_sibling(cgutils_rbtree_node const * const node)
{
    cgutils_rbtree_node * result = NULL;
    CGUTILS_ASSERT(node != NULL);
    CGUTILS_ASSERT(node->parent != NULL); /* Root node has no sibling */

    if (node == node->parent->left)
    {
        result = node->parent->right;
    }
    else
    {
        result = node->parent->left;
    }

    return result;
}

static cgutils_rbtree_node * cgutils_rbtree_uncle(cgutils_rbtree_node const * const node)
{
    CGUTILS_ASSERT(node != NULL);
    CGUTILS_ASSERT(node->parent != NULL); /* Root node has no uncle */
    CGUTILS_ASSERT(node->parent->parent != NULL); /* Children of root have no uncle */

    return cgutils_rbtree_sibling(node->parent);
}

static cgutils_rbtree_node * cgutils_rbtree_maximum_node(cgutils_rbtree_node * node)
{
    CGUTILS_ASSERT(node != NULL);

    while (node->right != NULL)
    {
        node = node->right;
    }

    return node;
}

#ifdef DEBUG_RBTREE
static void cgutils_rbtree_verify_property_1(cgutils_rbtree_node const * const node)
{
    if (node != NULL)
    {
        CGUTILS_ASSERT(cgutils_rbtree_node_color(node) == cgutils_rbtree_color_red ||
                       cgutils_rbtree_node_color(node) == cgutils_rbtree_color_black);

        cgutils_rbtree_verify_property_1(node->left);
        cgutils_rbtree_verify_property_1(node->right);
    }
}

static void cgutils_rbtree_verify_property_2(cgutils_rbtree_node const * const root)
{
    CGUTILS_ASSERT(cgutils_rbtree_node_color(root) == cgutils_rbtree_color_black);
}

static void cgutils_rbtree_verify_property_4(cgutils_rbtree_node const * const node)
{
    if (node != NULL)
    {
        if (cgutils_rbtree_node_color(node) == cgutils_rbtree_color_red)
        {
            CGUTILS_ASSERT(cgutils_rbtree_node_color(node->left) == cgutils_rbtree_color_black);

            CGUTILS_ASSERT(cgutils_rbtree_node_color(node->right) == cgutils_rbtree_color_black);

            CGUTILS_ASSERT(cgutils_rbtree_node_color(node->parent) == cgutils_rbtree_color_black);
        }

        cgutils_rbtree_verify_property_4(node->left);
        cgutils_rbtree_verify_property_4(node->right);
    }
}

static void cgutils_rbtree_verify_property_5_helper(cgutils_rbtree_node const * const node,
                                                    ssize_t black_count,
                                                    ssize_t * const path_black_count)
{
    if (cgutils_rbtree_node_color(node) == cgutils_rbtree_color_black)
    {
        black_count++;
    }

    if (node == NULL)
    {
        if (*path_black_count == -1)
        {
            *path_black_count = black_count;
        }
        else
        {
            CGUTILS_ASSERT(black_count == *path_black_count);
        }
    }
    else
    {
        cgutils_rbtree_verify_property_5_helper(node->left,
                                                black_count,
                                                path_black_count);

        cgutils_rbtree_verify_property_5_helper(node->right,
                                                black_count,
                                                path_black_count);
    }
}

static void cgutils_rbtree_verify_property_5(cgutils_rbtree_node const * const root)
{
    ssize_t black_count_path = -1;
    cgutils_rbtree_verify_property_5_helper(root,
                                            0,
                                            &black_count_path);
}

#endif /* DEBUG_RBTREE */

static void cgutils_rbtree_verify_properties(cgutils_rbtree const * const tree)
{
    CGUTILS_ASSERT(tree != NULL);
#ifdef DEBUG_RBTREE
    cgutils_rbtree_verify_property_1(tree->root);
    cgutils_rbtree_verify_property_2(tree->root);
    /* Property 3 is implicit */
    cgutils_rbtree_verify_property_4(tree->root);
    cgutils_rbtree_verify_property_5(tree->root);
#else
    (void) tree;
#endif /* DEBUG_RBTREE */
}

int cgutils_rbtree_init(cgutils_rbtree_compare * const compare,
                        cgutils_rbtree_key_delete * const key_del,
                        cgutils_rbtree_value_delete * const value_del,
                        cgutils_rbtree ** const out)
{
    int result = EINVAL;

    if (compare != NULL &&
        key_del != NULL &&
        value_del != NULL &&
        out != NULL)
    {
        cgutils_rbtree * this = NULL;

        result = 0;

        CGUTILS_ALLOCATE_STRUCT(this);

        if (this != NULL)
        {
            this->compare = compare;
            this->key_del = key_del;
            this->value_del = value_del;
            *out = this;

            cgutils_rbtree_verify_properties(*out);
        }
        else
        {
            result = ENOMEM;
        }

        *out = this;
    }

    return result;
}

static int cgutils_rbtree_node_init(void * const key,
                                    void * const value,
                                    cgutils_rbtree_color const color,
                                    cgutils_rbtree_node ** const out)
{
    int result = 0;
    cgutils_rbtree_node * node = NULL;

    CGUTILS_ASSERT(key != NULL);
    CGUTILS_ASSERT(value != NULL);
    CGUTILS_ASSERT(out != NULL);

    CGUTILS_ALLOCATE_STRUCT(node);

    if (COMPILER_LIKELY(node != NULL))
    {
        node->key = key;
        node->value = value;
        node->color = color;
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        *out = node;
    }
    else
    {
        result = ENOMEM;
    }

    return result;
}

int cgutils_rbtree_get(cgutils_rbtree const * const tree,
                       void const * const key,
                       cgutils_rbtree_node ** const out)
{
    int result = 0;

    if (COMPILER_LIKELY(tree != NULL &&
                        key != NULL &&
                        out != NULL))
    {
        cgutils_rbtree_node * node = tree->root;
        cgutils_rbtree_compare * const compare = tree->compare;
        CGUTILS_ASSERT(compare != NULL);

        result = ENOENT;

        while (result == ENOENT &&
               node != NULL)
        {
            int const res = (*compare)(key, node->key);

            if (res < 0)
            {
                node = node->left;
            }
            else if (res > 0)
            {
                node = node->right;
            }
            else
            {
                result = 0;
                *out = node;
            }
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

void * cgutils_rbtree_node_get_value(cgutils_rbtree_node const * const node)
{
    void * result = NULL;

    if (COMPILER_LIKELY(node != NULL))
    {
        result = node->value;
    }

    return result;
}

static void cgutils_rbtree_replace_node(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const old,
                                        cgutils_rbtree_node * const new)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(old != NULL);

    if (COMPILER_LIKELY(old->parent != NULL))
    {
        if (old == old->parent->left)
        {
            old->parent->left = new;
        }
        else
        {
            old->parent->right = new;
        }
    }
    else
    {
        /* if the old node was the root,
           the new node becomes the root. */
        tree->root = new;
    }

    if (new != NULL)
    {
        new->parent = old->parent;
    }
}

static void cgutils_rbtree_rotate_left(cgutils_rbtree * const tree,
                                       cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    cgutils_rbtree_node * const right = node->right;

    cgutils_rbtree_replace_node(tree,
                                node,
                                right);

    node->right = right->left;

    if (right->left != NULL)
    {
        right->left->parent = node;
    }

    right->left = node;
    node->parent = right;
}

static void cgutils_rbtree_rotate_right(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    cgutils_rbtree_node * left = node->left;

    cgutils_rbtree_replace_node(tree, node, left);

    node->left = left->right;

    if (left->right != NULL)
    {
        left->right->parent = node;
    }

    left->right = node;
    node->parent = left;
}

static void cgutils_rbtree_insert_case5(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);
    cgutils_rbtree_node * const grand = cgutils_rbtree_grandparent(node);

    node->parent->color = cgutils_rbtree_color_black;
    grand->color = cgutils_rbtree_color_red;

    if (node == node->parent->left &&
        node->parent == grand->left)
    {
        cgutils_rbtree_rotate_right(tree,
                                    grand);
    }
    else
    {
        CGUTILS_ASSERT(node == node->parent->right &&
                       node->parent == grand->right);

        cgutils_rbtree_rotate_left(tree,
                                   grand);
    }
}

static void cgutils_rbtree_insert_case4(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    if (node == node->parent->right &&
        node->parent == cgutils_rbtree_grandparent(node)->left)
    {
        cgutils_rbtree_rotate_left(tree,
                                   node->parent);
        node = node->left;

    }
    else if (node == node->parent->left &&
             node->parent == cgutils_rbtree_grandparent(node)->right)
    {
        cgutils_rbtree_rotate_right(tree, node->parent);

        node = node->right;
    }

    cgutils_rbtree_insert_case5(tree,
                                node);
}

static void cgutils_rbtree_insert_case1(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node);

static void cgutils_rbtree_insert_case3(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    cgutils_rbtree_node * const uncle = cgutils_rbtree_uncle(node);

    if (cgutils_rbtree_node_color(uncle) == cgutils_rbtree_color_red)
    {
        node->parent->color = cgutils_rbtree_color_black;
        uncle->color = cgutils_rbtree_color_black;
        cgutils_rbtree_grandparent(node)->color = cgutils_rbtree_color_red;

        cgutils_rbtree_insert_case1(tree,
                                    cgutils_rbtree_grandparent(node));
    }
    else
    {
        cgutils_rbtree_insert_case4(tree,
                                    node);
    }
}

static void cgutils_rbtree_insert_case2(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    if (cgutils_rbtree_node_color(node->parent) == cgutils_rbtree_color_red)
    {
        cgutils_rbtree_insert_case3(tree,
                                    node);
    }
}

static void cgutils_rbtree_insert_case1(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    if (COMPILER_LIKELY(node->parent != NULL))
    {
        cgutils_rbtree_insert_case2(tree,
                                    node);
    }
    else
    {
        node->color = cgutils_rbtree_color_black;
    }
}

int cgutils_rbtree_insert(cgutils_rbtree * const tree,
                          void * const key,
                          void * const value)
{
    int result = 0;

    if (COMPILER_LIKELY(tree != NULL &&
                        key != NULL))
    {
        cgutils_rbtree_node * new_node = NULL;

        result = cgutils_rbtree_node_init(key,
                                          value,
                                          cgutils_rbtree_color_red,
                                          &new_node);

        if (COMPILER_LIKELY(result == 0))
        {
            if (COMPILER_LIKELY(tree->root != NULL))
            {
                bool finished = false;
                cgutils_rbtree_node * node = tree->root;
                cgutils_rbtree_compare * const compare = tree->compare;
                CGUTILS_ASSERT(compare != NULL);

                while (result == 0 &&
                       finished ==false )
                {
                    int const res = (*compare)(key,
                                               node->key);

                    if (res < 0)
                    {
                        if (node->left != NULL)
                        {
                            node = node->left;
                        }
                        else
                        {
                            node->left = new_node;
                            finished = true;
                        }
                    }
                    else if (res > 0)
                    {
                        if (node->right != NULL)
                        {
                            node = node->right;
                        }
                        else
                        {
                            node->right = new_node;
                            finished = true;
                        }
                    }
                    else
                    {
                        result = EEXIST;
                    }
                }

                if (COMPILER_LIKELY(result == 0))
                {
                    new_node->parent = node;
                }
            }
            else
            {
                tree->root = new_node;
            }

            cgutils_rbtree_insert_case1(tree,
                                        new_node);

            cgutils_rbtree_verify_properties(tree);

            if (COMPILER_UNLIKELY(result != 0))
            {
                CGUTILS_FREE(new_node);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static void cgutils_rbtree_delete_case6(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    cgutils_rbtree_node * const sibling = cgutils_rbtree_sibling(node);
    CGUTILS_ASSERT(sibling != NULL);

    sibling->color = cgutils_rbtree_node_color(node->parent);
    node->parent->color = cgutils_rbtree_color_black;

    if (node == node->parent->left)
    {
        CGUTILS_ASSERT(cgutils_rbtree_node_color(sibling->right) == cgutils_rbtree_color_red);

        sibling->right->color = cgutils_rbtree_color_black;
        cgutils_rbtree_rotate_left(tree,
                                   node->parent);
    }
    else
    {
        CGUTILS_ASSERT(cgutils_rbtree_node_color(sibling->left) == cgutils_rbtree_color_red);

        sibling->left->color = cgutils_rbtree_color_black;
        cgutils_rbtree_rotate_right(tree,
                                    node->parent);
    }
}

static void cgutils_rbtree_delete_case5(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    cgutils_rbtree_node * const sibling = cgutils_rbtree_sibling(node);

    if (cgutils_rbtree_node_color(sibling) == cgutils_rbtree_color_black)
    {
        if (node == node->parent->left &&
            cgutils_rbtree_node_color(sibling->left) == cgutils_rbtree_color_red &&
            cgutils_rbtree_node_color(sibling->right) == cgutils_rbtree_color_black)
        {
            sibling->color = cgutils_rbtree_color_red;
            sibling->left->color = cgutils_rbtree_color_black;
            cgutils_rbtree_rotate_right(tree,
                                        sibling);
        }
        else if (node == node->parent->right &&
                 cgutils_rbtree_node_color(sibling->right) == cgutils_rbtree_color_red &&
                 cgutils_rbtree_node_color(sibling->left) == cgutils_rbtree_color_black)
        {
            sibling->color = cgutils_rbtree_color_red;
            sibling->right->color = cgutils_rbtree_color_black;
            cgutils_rbtree_rotate_left(tree,
                                       sibling);
        }
    }

    cgutils_rbtree_delete_case6(tree, node);
}

static void cgutils_rbtree_delete_case4(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);
    cgutils_rbtree_node * const sibling = cgutils_rbtree_sibling(node);

    if (cgutils_rbtree_node_color(node->parent) == cgutils_rbtree_color_red &&
        cgutils_rbtree_node_color(sibling) == cgutils_rbtree_color_black &&
        cgutils_rbtree_node_color(sibling->left) == cgutils_rbtree_color_black &&
        cgutils_rbtree_node_color(sibling->right) == cgutils_rbtree_color_black)
    {
        sibling->color = cgutils_rbtree_color_red;
        node->parent->color = cgutils_rbtree_color_black;
    }
    else
    {
        cgutils_rbtree_delete_case5(tree,
                                    node);
    }
}

static void cgutils_rbtree_delete_case1(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node);

static void cgutils_rbtree_delete_case3(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);
    cgutils_rbtree_node * const sibling = cgutils_rbtree_sibling(node);

    if (cgutils_rbtree_node_color(node->parent) == cgutils_rbtree_color_black &&
        cgutils_rbtree_node_color(sibling) == cgutils_rbtree_color_black &&
        cgutils_rbtree_node_color(sibling->left) == cgutils_rbtree_color_black &&
        cgutils_rbtree_node_color(sibling->right) == cgutils_rbtree_color_black)
    {
        sibling->color = cgutils_rbtree_color_red;
        cgutils_rbtree_delete_case1(tree,
                                    node->parent);
    }
    else
    {
        cgutils_rbtree_delete_case4(tree,
                                    node);
    }
}

static void cgutils_rbtree_delete_case2(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);
    cgutils_rbtree_node * const sibling = cgutils_rbtree_sibling(node);

    if (cgutils_rbtree_node_color(sibling) == cgutils_rbtree_color_red)
    {
        node->parent->color = cgutils_rbtree_color_red;
        sibling->color = cgutils_rbtree_color_black;

        if (node == node->parent->left)
        {
            cgutils_rbtree_rotate_left(tree,
                                       node->parent);
        }
        else
        {
            cgutils_rbtree_rotate_right(tree,
                                        node->parent);
        }
    }

    cgutils_rbtree_delete_case3(tree,
                                node);
}

static void cgutils_rbtree_delete_case1(cgutils_rbtree * const tree,
                                        cgutils_rbtree_node * const node)
{
    CGUTILS_ASSERT(tree != NULL);
    CGUTILS_ASSERT(node != NULL);

    if (COMPILER_LIKELY(node->parent != NULL))
    {
        cgutils_rbtree_delete_case2(tree,
                                    node);
    }
}

int cgutils_rbtree_remove(cgutils_rbtree * const tree,
                          cgutils_rbtree_node * node)
{
    int result = 0;

    if (COMPILER_LIKELY(tree != NULL &&
                        node != NULL))
    {
        void * key = node->key;
        void * value = node->value;

        if (node->left != NULL &&
            node->right != NULL)
        {
            /* Copy key/value from predecessor and then delete it instead */
            cgutils_rbtree_node * predecessor = cgutils_rbtree_maximum_node(node->left);
            CGUTILS_ASSERT(predecessor != NULL);

            node->key = predecessor->key;
            node->value = predecessor->value;
            node = predecessor;
        }

        CGUTILS_ASSERT(node->left == NULL ||
                       node->right == NULL);

        cgutils_rbtree_node * child = node->right == NULL ? node->left : node->right;

        if (cgutils_rbtree_node_color(node) == cgutils_rbtree_color_black)
        {
            node->color = cgutils_rbtree_node_color(child);

            cgutils_rbtree_delete_case1(tree,
                                        node);
        }

        cgutils_rbtree_replace_node(tree,
                                    node,
                                    child);

        if (node->parent == NULL &&
            child != NULL)
        {
            /* root should be black */
            child->color = cgutils_rbtree_color_black;
        }

        node->key = key;
        node->value = value;
        cgutils_rbtree_node_free(tree,
                                 node);
        node = NULL;

        cgutils_rbtree_verify_properties(tree);
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static void cgutils_rbtree_destroy_recursive(cgutils_rbtree * const this,
                                             cgutils_rbtree_node * node)
{
    CGUTILS_ASSERT(this != NULL);

    if (node != NULL)
    {
        cgutils_rbtree_destroy_recursive(this, node->left);
        cgutils_rbtree_destroy_recursive(this, node->right);
        cgutils_rbtree_node_free(this, node);
    }
}

void cgutils_rbtree_destroy(cgutils_rbtree * this)

{
    if (this != NULL)
    {
        cgutils_rbtree_destroy_recursive(this,
                                         this->root);
        CGUTILS_FREE(this);
    }
}
