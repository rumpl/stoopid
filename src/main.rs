use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = args[1].parse::<i32>().unwrap();

    let wait = args.len() == 3;

    for i in 0..n {
        let filename = format!("file_{}", i);
        let mut c = Command::new("touch")
            .arg(filename)
            .spawn()
            .expect("failed to execute process");
        if wait {
            c.wait().expect("failed to wait process");
        }
    }

    let mut c = Command::new("cat")
        .arg(format!("file_{}", n - 1))
        .spawn()
        .expect("failed to execute process");
    if wait {
        c.wait().expect("failed to wait process");
    }
}
