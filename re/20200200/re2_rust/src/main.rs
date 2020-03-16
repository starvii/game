// flag{7230deb0-e1e6-4296-b283-d1141c04593b}

fn main() {
    use std::io::stdin;
    let mut line = String::new();
    print(b"Please guess the flag: ");
    stdin().read_line(&mut line).expect("Failed to read line.");
    line = line.trim().to_string();
    let b = line.as_bytes();
    // let bytes = unsafe{line.as_bytes_mut()};
    let n = b.len();
    if n != 42 {
        exit();
    }
    if &b[0..5] != b"flag{" {
        exit();
    }
    if &b[n - 1 .. n] != b"}" {
        exit();
    }
    let c = String::from(&line[5 .. n - 1]).replace("-", "");
    const N: usize = 32;
    // const CORRECT: &[u8] = b"\x72\x30\xde\xb0\xe1\xe6\x42\x96\xb2\x83\xd1\x14\x1c\x04\x59\x3b";
    if c.len() != N {
        exit();
    }
    let mut buf: [u8; N] = [0; N];
    let b = c.as_bytes();
    for i in 0 .. N {
        buf[i] = b[i];
    }
    const C: [u8; 32] = [7, 2, 3, 0, 13, 14, 11, 0, 14, 1, 14, 6, 4, 2, 9, 6, 11, 2, 8, 3, 13, 1, 1, 4, 1, 12, 0, 4, 5, 9, 3, 11];
    for i in 0 .. N {
        let c = buf[i];
        let x: u8 = if c >= b'0' && c <= b'9' {
            c - b'0'
        } else if c >= b'a' && c <= b'f' {
            c - b'a' + 10
        } else {
            exit();
            0
        };
        if x != C[i] {
            exit();
        }
    }
    print(b"Congratulations!\n");
}

fn print(text_bytes: &[u8]) {
    use std::io::Write;
    use std::io::stdout;
    stdout().write_all(text_bytes).expect("Failed to write all.");
    stdout().flush().expect("Failed to flush.");
}

fn exit() {
    print(b"Not correct. Please try again.\n");
    std::process::exit(0);
}
