extern crate regex;
extern crate lazy_static;

use reqwest;
use tokio;
use select::node::Node;
use select::document::Document;
// 正则
use lazy_static::lazy_static;
use regex::Regex;
// 文件
use std::fs::File;
use std::io::Write;
use std::io;
// 时间
use std::time::{Instant};


// 使用 lazy_static 宏创建静态正则表达式对象，可以在第一次使用正则表达式时初始化它们，以后就不需要再次编译，主要用来优化性能，减少不必要的开销。
lazy_static! {
    static ref ASN_REGEX: Regex = Regex::new(r#"^AS([1-9]\d{0,5})$"#).unwrap();
    static ref IPV4_CIDR_RE: Regex = Regex::new(r#"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$"#).unwrap();
    static ref IPV6_CIDR_RE: Regex = Regex::new(r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?$").unwrap();
}

fn wait_for_enter() {
    let mut input = String::new();
    print!("按下Enter键关闭窗口...");
    io::stdout().flush().expect("刷新输出缓冲区失败");
    io::stdin().read_line(&mut input).expect("读取输入失败");
}

fn get_user_input() -> String {
    loop {
        print!("输入一个ASN自治系统编号(输入范围：AS1……AS999999):");
        io::stdout().flush().expect("刷新输出缓冲区失败");
        let mut asn = String::new();

        // 从控制台获取用户输入
        io::stdin().read_line(&mut asn).expect("无法读取输入");

        // 去除输入中的换行符并转为大写
        asn = asn.trim().to_string().to_ascii_uppercase();

        // 检查输入是否匹配 ASN 正则表达式
        if ASN_REGEX.is_match(&asn) {
            return asn;
        } else {
            // eprintln!("输入的ASN不符合要求。请重新输入。");
        }
    }
}

async fn get_asn_data(asn: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("https://whoisrequest.com/ip/{}", asn);

    // 创建一个reqwest客户端并添加User-Agent头
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36")
        .build()?;
    // 记录请求的时间
    let start = Instant::now();
    // 发送HTTP GET请求
    let response = client.get(&url).send().await?;

    // 请求成功，状态码是200
    if response.status().is_success() {
        let html_doc = response.text().await?;
        let document = Document::from_read(html_doc.as_bytes())?;
        println!("");

        let mut matched_texts: Vec<String> = Vec::new(); // 创建一个 Vec 用于存储匹配成功的文本


        // 找到具体的元素（在这个标签中找a标签，排除这个标签外的其他a标签）
        if let Some(prefix_table) = document.find(|n: &Node| {
            n.name() == Some("table")
                && n.attr("id").map(|attr| attr == "prefix-table").unwrap_or(false)
        }).next() {
            for node in prefix_table.find(|n: &Node| n.name() == Some("a")) {
                let text = node.text();
                let trimmed_text = text.trim().to_string(); // 转换为String类型
                // 使用正则表达式匹配 trimmed_text
                if IPV4_CIDR_RE.is_match(&trimmed_text) || IPV6_CIDR_RE.is_match(&trimmed_text) {
                    println!("{}", &trimmed_text); // 实时打印捕捉到的CIDR数据
                    matched_texts.push(trimmed_text); // 将trimmed_text添加到向量matched_texts中
                }
            }
        }
        match matched_texts.is_empty() {
            true => {
                // matched_texts 为空的情况
                println!("\n没有找到相关的数据！");
            }
            false => {
                let mut file = File::create(format!("{}_whoisrequest.com_CIDRs.txt", asn))?;
                // 打印匹配成功的文本（最终获取的结果）
                for text in matched_texts {
                    writeln!(file, "{}", text)?;
                    file.flush()?; // 立即刷新文件缓冲,将数据刷新到文件
                }
                println!("\n{}自治系统中，公开的IPv4、IPv6前缀(也就是CIDR)下载成功！耗时：{:?}", asn, start.elapsed());
            }
        }
    } else {
        println!("无法打开URL链接：{}", url);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("本工具：用于下载网站 https://whoisrequest.com/ip 中，公开的IPv4、IPv6前缀(也就是CIDR)。\n");

    // 从控制台获取用户输入的asn
    let asn = get_user_input();

    // 获取asn对应的数据
    get_asn_data(&asn).await?;

    wait_for_enter();
    Ok(())
}