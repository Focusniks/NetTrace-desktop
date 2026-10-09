//! A FIFO that stores up to one element inline: most TCP connections of a
//! capture never have more than one segment in flight per direction (a SYN,
//! a lone request), so they never allocate.

use std::collections::VecDeque;

#[derive(Debug, Clone, Default)]
pub(crate) enum Ring<T> {
    #[default]
    Empty,
    One(T),
    Many(VecDeque<T>),
}

impl<T: Copy> Ring<T> {
    pub fn len(&self) -> usize {
        match self {
            Ring::Empty => 0,
            Ring::One(_) => 1,
            Ring::Many(q) => q.len(),
        }
    }

    pub fn front(&self) -> Option<&T> {
        match self {
            Ring::Empty => None,
            Ring::One(x) => Some(x),
            Ring::Many(q) => q.front(),
        }
    }

    pub fn pop_front(&mut self) -> Option<T> {
        match self {
            Ring::Empty => None,
            Ring::One(x) => {
                let x = *x;
                *self = Ring::Empty;
                Some(x)
            }
            Ring::Many(q) => q.pop_front(),
        }
    }

    pub fn push_back(&mut self, item: T) {
        match self {
            Ring::Empty => *self = Ring::One(item),
            Ring::One(x) => *self = Ring::Many(VecDeque::from([*x, item])),
            Ring::Many(q) => q.push_back(item),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        let (one, many) = match self {
            Ring::Empty => (None, None),
            Ring::One(x) => (Some(x), None),
            Ring::Many(q) => (None, Some(q.iter())),
        };
        one.into_iter().chain(many.into_iter().flatten())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        let (one, many) = match self {
            Ring::Empty => (None, None),
            Ring::One(x) => (Some(x), None),
            Ring::Many(q) => (None, Some(q.iter_mut())),
        };
        one.into_iter().chain(many.into_iter().flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaves_like_a_fifo() {
        let mut r = Ring::default();
        assert_eq!((r.len(), r.front()), (0, None));
        r.push_back(1);
        assert!(matches!(r, Ring::One(1)));
        r.push_back(2);
        r.push_back(3);
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), [1, 2, 3]);
        for x in r.iter_mut() {
            *x *= 10;
        }
        assert_eq!(r.pop_front(), Some(10));
        assert_eq!((r.len(), r.front()), (2, Some(&20)));
        assert_eq!((r.pop_front(), r.pop_front(), r.pop_front()), (Some(20), Some(30), None));

        let mut one = Ring::default();
        one.push_back(7);
        assert_eq!((one.pop_front(), one.len()), (Some(7), 0));
    }
}
