class LinkedList:
  "A doubly linked list.  Allows us to do fast deletion of references."
  def __init__(self):
    self.last = None
    self.first = None
    self.length = 0

  def __contains__(self, node):
    p = self.first
    while p != None:
      if node == p:
        return True
      p = p.next
    return False

  def __iter__(self):
    return LinkedListIterator(self.first)

  def __repr__(self):
    list = []
    node = self.first
    while node:
      list.append(node.data)
      node = node.next
    return "LL:" + repr(list)

  def append(self, data):
    if self.last:
      node = ListNode(data)
      self.last.next = node
      node.prev = self.last
      self.last = node
    else:
      self.first = self.last = ListNode(data)
    self.length += 1

  def delete(self, node):
    assert node.valid, 'deleting already-deleted node'
    if node.prev:
      node.prev.next = node.next
    else:
      self.first = node.next
    if node.next:
      node.next.prev = node.prev
    else:
      self.last = node.prev
    node.valid = False
    del node
    self.length -= 1

  def __del__(self):
    """ delete all the nodes when we get deleted """
    node = self.first
    while node != None:
      next = node.next
      del node # zeros next and prev pointers
      node = next
    self.first = None
    self.last = None
    self.length = 0
      
  def __len__(self):
    return self.length


class ListNode:

  def __init__(self, data):
    self.prev = None
    self.next = None
    self.data = data
    self.valid = True

  def __del__(self):
    self.prev = None
    self.next = None
    if self.data != None:
      del self.data
    self.valid = False

  def __repr__(self):
    str = "ListNode:"
    if self.prev:
      str += repr(self.prev.data) + "<-"
    str += repr(self.data)
    if self.next:
      str+= "->" + repr(self.next.data)
    return str


class LinkedListIterator:
  def __init__(self, start_node):
    self.node = start_node
  def __iter__(self):
    return self
  def next(self):
    p = self.node
    if p == None:
      raise StopIteration
    self.node = self.node.next
    return p

