


pub struct ByteMatrix {
    matrix: Vec<Vec<u8>>,
    row_size: usize,
}


impl ByteMatrix {
    pub fn transpose(vector: &[u8], size: usize) -> ByteMatrix {
        let mut vectors: Vec<Vec<u8>> = Vec::new();
        for i in (1..size + 1) {
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
        for (i, _) in self.matrix.iter().enumerate() {
            for j in (0..self.row_size) {
                bytes.push(self.matrix[j][i]);
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
        let text = "lalalala";
        let matrix = ByteMatrix::transpose(text.as_bytes(), 2);
        let bytes = matrix.reassemble();
        let out = str::from_utf8(&bytes).unwrap();
        assert_eq!(text, out);
    }
}
