use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let run_id = args[1].parse::<i32>().unwrap();
    let n = args[2].parse::<i32>().unwrap();

    let wait = args.len() == 4;

    for i in 0..n {
        let filename = format!("file_{}_{}", run_id, i);
        let mut c = Command::new("touch")
            .arg(filename)
            .spawn()
            .expect("failed to execute process");
        if wait {
            c.wait().expect("failed to wait process");
        }
    }

    let mut c = Command::new("cat")
        .arg(format!("file_{}_{}", run_id, n - 1))
        .spawn()
        .expect("failed to execute process");
    if wait {
        c.wait().expect("failed to wait process");
    }
}
