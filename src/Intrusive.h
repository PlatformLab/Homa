/* Copyright (c) 2019, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HOMA_CORE_INTRUSIVE_H
#define HOMA_CORE_INTRUSIVE_H

namespace Homa {
namespace Core {
/**
 * Contains various intrusive style data structures.
 *
 * Intrusive data structures allow data structure metadata to be contained in
 * and allocated with the elements themselves.  Intrusive data structures are
 * often used to avoid incurring additional memory allocation when frequently
 * adding and removing elements from a data structure.
 */
namespace Intrusive {

/**
 * Double-Link List implementation.
 */
template <typename ElementType>
class List {
  public:
    class Iterator;

    /**
     * The intrusive metadata needed to add and remove an element from the List.
     */
    class Node {
      public:
        /**
         * List::Node constructor.
         *
         * @param owner
         *      Pointer to the object of which this Node is a member.
         */
        explicit Node(ElementType* owner)
            : owner(owner)
            , list(nullptr)
            , next(this)
            , prev(this)
        {}

        /**
         * List::Node destructor.
         */
        ~Node()
        {
            // Assert that the Node is cleanly removed from any List.
            assert(next == this);
            assert(prev == this);
        }

      private:
        /**
         * Remove this Node from the List to which it is linked (if any).
         */
        inline void unlink()
        {
            next->prev = prev;
            prev->next = next;
            next = this;
            prev = this;
            list = nullptr;
        }

        /// Pointer to the element object that this Node represents.
        ElementType* const owner;
        /// Pointer to the List to which this Node is currently linked.
        List* list;
        /// Pointer to the next Node in the List.
        Node* next;
        /// Pointer to the previous Node in the List.
        Node* prev;

        friend class List;
        friend class Iterator;
    };

    /**
     * A dereferenceable reference to an element in the list.
     */
    class Iterator {
      public:
        /**
         * Iterator empty constructor.
         */
        Iterator()
            : node(nullptr)
        {}

        /**
         * Return a reference to the element referred to by this Iterator.
         */
        ElementType& operator*()
        {
            return *node->owner;
        }

        /**
         * Access member of the element referred to by this Iterator.
         */
        ElementType* operator->()
        {
            return node->owner;
        }

        /**
         * Point this Iterator to the next element in the List.
         *
         * @return
         *      A reference to the updated Iterator.
         */
        Iterator& operator++()
        {
            node = node->next;
            return *this;
        }

        /**
         * Pointer this Iterator to the previous element in the List.
         *
         * @return
         *      A reference to the updated Iterator.
         */
        Iterator& operator--()
        {
            node = node->prev;
            return *this;
        }

        /**
         * Point this Iterator to the next element in the List.
         *
         * @return
         *      A reference a copy of the Iterator before the update.
         */
        Iterator operator++(int)
        {
            Iterator old = *this;
            node = node->next;
            return old;
        }

        /**
         * Pointer this Iterator to the previous element in the List.
         *
         * @return
         *      A reference a copy of the Iterator before the update.
         */
        Iterator operator--(int)
        {
            Iterator old = *this;
            node = node->prev;
            return old;
        }

        /**
         * Return true if both this and the other Iterator refer to the same
         * element in the List; false otherwise.
         */
        bool operator==(const Iterator& other) const
        {
            return node == other.node;
        }

        /**
         * Return true if both this and the other Iterator refer to different
         * elements in the List; false otherwise.
         */
        bool operator!=(const Iterator& other) const
        {
            return node != other.node;
        }

      private:
        /**
         * Iterator constructor.  Used be a List to create a valid Iterator.
         *
         * @param node
         *      Pointer to the Node to which this Iterator refers.
         */
        explicit Iterator(Node* node)
            : node(node)
        {}

        /// The Node to which this Iterator refers.
        Node* node;

        friend class List;
    };

    /**
     * List constructor.
     */
    List()
        : root(nullptr)
    {
        root.list = this;
    }

    /**
     * List destructor.
     */
    ~List()
    {
        clear();
    }

    /**
     * Return a reference to the first element in the List.
     *
     * Calling front() on an empty List is undefined.
     */
    ElementType& front()
    {
        return *root.next->owner;
    }

    /**
     * Return a reference to the last element in the List.
     *
     * Calling back() on an empty List is undefined.
     */
    ElementType& back()
    {
        return *root.prev->owner;
    }

    /**
     * Return an Iterator to the first element in the List.
     */
    Iterator begin()
    {
        return Iterator(root.next);
    }

    /**
     * Return an Iterator following the last element in the List.
     */
    Iterator end()
    {
        return Iterator(&root);
    }

    /**
     * Check if the List contains no elements.
     *
     * @return
     *      True, if there are no elements in this List; false, otherwise.
     */
    bool empty() const
    {
        return &root == root.next;
    }

    /**
     * Remove all linked Node from the List.
     *
     * Invalidates any Iterators referring to elements in this List.
     */
    void clear()
    {
        while (root.prev != &root) {
            root.prev->unlink();
        }
    };

    /**
     * Insert an element before pos.
     *
     * No Iterators are invalidated.
     *
     * @param pos
     *      Iterator before which the node will be inserted.
     * @param node
     *      Node element to be inserted.
     * @return
     *      Iterator pointing to the inserted node.
     */
    Iterator insert(Iterator pos, Node* node)
    {
        assert(pos.node->list == this);
        __insert(pos.node, node);
        return Iterator(node);
    }

    /**
     * Removes the node element at pos.
     *
     * Iterators referring to the removed element are invalidated.
     *
     * @param pos
     *      Iterator to the element to remove.
     * @return
     *      Iterator following the removed element.
     */
    Iterator remove(Iterator pos)
    {
        assert(pos.node->list == this || pos.node->list == nullptr);
        Iterator nextPos(pos.node->next);
        pos.node->unlink();
        return nextPos;
    }

    /**
     * Removes the node from this List.
     *
     * Iterators referring to the removed element are invalidated.
     *
     * @param node
     *      Node to be removed from this List.
     */
    void remove(Node* node)
    {
        assert(node->list == this || node->list == nullptr);
        node->unlink();
    }

    /**
     * Append an element to the end of the List.
     *
     * No Iterators are invalidated.
     *
     * @node
     *      Node element to be appended.
     */
    void push_back(Node* node)
    {
        __insert(&root, node);
    }

    /**
     * Remove the last element in the List.
     *
     * Iterators referring to the last element in the List are invalidated.
     *
     * Calling pop_back() on an empty List is undefined.
     */
    void pop_back()
    {
        root.prev->unlink();
    }

    /**
     * Prepend an element to the beginning of the List.
     *
     * No Iterators are invalidated.
     *
     * @node
     *      Node element to be prepended.
     */
    void push_front(Node* node)
    {
        __insert(root.next, node);
    }

    /**
     * Remove the first element of the List;
     *
     * Iterators referring to the first element in the List are invalidated.
     *
     * Calling pop_front() on an empty List is undefined.
     */
    void pop_front()
    {
        root.next->unlink();
    }

    /**
     * Check if the given element is in the List.
     *
     * @param node
     *      Node element being checked.
     * @return
     *      True, if the node is in the List; false, otherwise.
     */
    bool contains(Node* node)
    {
        return node->list == this;
    }

  private:
    /**
     * Insert node before pos (private helper method).
     *
     * @param pos
     *      Node before which node will be inserted and linked.
     * @param node
     *      Node which will be inserted and linked.
     */
    static inline void __insert(Node* pos, Node* node)
    {
        // Ensure the node is not already linked.
        assert(node->next == node);
        assert(node->prev == node);
        node->next = pos;
        node->prev = pos->prev;
        node->list = pos->list;
        pos->prev->next = node;
        pos->prev = node;
    }

    /// Entry point into the double-linked list of Nodes.
    Node root;
};

}  // namespace Intrusive
}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_INTRUSIVE_H
