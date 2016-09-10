


pub struct ByteMatrix {
    matrix: Vec<Vec<u8>>,
    row_size: usize,
}


impl ByteMatrix {
    pub fn transpose(vector: &[u8], size: usize) -> ByteMatrix {
        let mut vectors: Vec<Vec<u8>> = Vec::new();
        for _ in 1..size + 1 {
            vectors.push(Vec::new());
        }
        for (i, byte) in vector.iter().enumerate() {
            vectors[i % size].push(*byte);
        }

        ByteMatrix {
            matrix: vectors,
            row_size: size,
        }

    }


    pub fn transform<F>(&self, fun: F) -> ByteMatrix
        where F: FnMut(&Vec<u8>) -> Vec<u8>
    {

        let vecs = self.matrix.iter().map(fun).collect();
        ByteMatrix {
            matrix: vecs,
            row_size: self.row_size,
        }

    }

    pub fn reassemble(&self) -> Vec<u8> {

        let mut bytes: Vec<u8> = Vec::new();
        let max_size = self.matrix[0].len();
        for i in 0..max_size {
            for j in 0..self.row_size {
                let this_size = self.matrix[j].len();
                if this_size > i {
                    bytes.push(self.matrix[j][i]);
                }
            }
        }
        bytes

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn test_transpose_and_back() {

        check_transpose_and_back("lalalala", 2);
        check_transpose_and_back("lalalal", 2);
        check_transpose_and_back("lalala", 2);

        check_transpose_and_back("this is a Random test to see if it works", 3);
        check_transpose_and_back("Let's try this again", 7);
        check_transpose_and_back("And another time to see what happens", 2);

        check_transpose_and_back("A", 3);
        check_transpose_and_back("And another time to see what happens", 1);

    }

    fn check_transpose_and_back(text: &str, size: usize) {
        let matrix = ByteMatrix::transpose(text.as_bytes(), size);
        let bytes = matrix.reassemble();
        let out = str::from_utf8(&bytes).unwrap();
        assert_eq!(text, out);
    }
}
