//! Port of `validate_test.go`. Differences from the Go suite are marked `CHANGED`.

use std::collections::HashMap;

use super::{Command, Registry, RegistryError, lex::split_words};

/// Same as the Go `cmds` map, minus templates the Go code silently treated as
/// never-matching. Those are now load-time errors (see `rejected_templates`).
fn commands() -> HashMap<&'static str, Command> {
    let registry = Registry::new(
        [
            r"/etc/(fstab|sysctl\.conf|passwd|group|exports)",
            r"/etc/sysconfig/network-scripts/[a-zA-Z0-9.-]+$",
        ],
        [("custom", "custom[0-9]+")],
    )
    .unwrap();
    let specs: &[(&str, &[&str], &[&str])] = &[
        ("grep", &["{{text:PATTERN}} {{path:FILE:o}}"], &[]),
        ("dmidecode", &["-t {{name:TYPE}}", "-t"], &[]),
        // dropped: "/etc/{{text:MSG:o}}"
        (
            "echo",
            &[
                "{{text:MSG}} test",
                "/etc/{{name:FILE}}.txt",
                "{{text:MSG:o}}",
            ],
            &[],
        ),
        (
            "ansible-playbook",
            &[
                "{{{/opt/foo/playbook}}}/{{name:PATH}}/{{name:PATH}} -k",
                "/home/test/playbook/{{name:PATH}} -k",
                "/home/test/playbook/{{name:PATH}}/{{name:PATH}} -k",
            ],
            &[],
        ),
        ("date", &["'+%s'", "'+%Y%m%d %H:%M:%S'"], &[]),
        (
            "cat",
            &[
                "{{name}}",
                "/proc/{{number}}",
                "/opt/{{name}}/data",
                "/opt/{{number}}/foo/{{name}}",
            ],
            &[],
        ),
        ("tcping", &["{{ipv4:IP}}:{{port:PORT}}"], &[]),
        ("telnet", &["{{ipv4}} {{port}}"], &[]),
        (
            "curl",
            &[
                "{{ipv4}}:{{port}}",
                "127.0.0.1:{{number:PORT}}/monitor/process?sort={{name:FIELD}}",
            ],
            &[],
        ),
        (
            "invalid",
            &[r#""" {{name}}"#, r#"{{port}} """#, "{{name:have space}}"],
            &[],
        ),
        ("vpninfo", &["-s {{name}}", "--sh"], &[]),
        ("dmesg", &[""], &["-h", "-T", "-hT"]),
        ("ls", &["{{anypath:PATH}}"], &["-h", "-l", "-lh"]),
        // dropped: "foo{{anypath:ANY}}"
        (
            "psudocmd",
            &[
                "{{{/book}}} math{{alpha:A-Z}}-{{digit:0-9}} {{text}}",
                "server{{number}}{{{v}}} -c",
                "foo{{{bar}}}dir",
                "{{{/home}}}{{{/test}}}/{{name}}/{{name}}",
                "{{text}}end",
                "{{name}}{world}",
            ],
            &[],
        ),
        // dropped: "{{{test}}}{{number:NUM:o}}"
        (
            "psudoOpt",
            &[
                "{{text::o}} {{anypath::o}} {{any::o}}",
                "{{name}} {{number::o}} {{number::o}} {{name::o}} {{name}}",
                "{{number}} {{text:TEXT:o}} {{path::o}}",
            ],
            &["-k"],
        ),
        // dropped: "{{datetime::o}}-00:00"
        (
            "psudoOpt2",
            &[
                "{{name}} {{number::o}} {{name::o}} {{name}}",
                "{{number}} {{text:TEXT:o}} {{path::o}}",
            ],
            &["-k"],
        ),
        (
            "psudoMul",
            &[
                "{{text::m}}",
                "{{port}} {{datetime::om}} {{ipv4::om}} end",
                "{{port::om}}",
            ],
            &["-a", "-r"],
        ),
        (
            "psudoMul2",
            &[
                "{{port}} {{number::m}} {{name::o}} {{name}}",
                "{{port}} {{number::m}} {{name::o}} {{datetime}}",
                "",
            ],
            &["-a", "-r"],
        ),
        (
            "psudoMul3",
            &[
                "{{text::om}} {{number::om}} {{alpha::om}} {{name::om}}",
                "{{any::m}} never be match",
            ],
            &["-a", "-r"],
        ),
        (
            "psudoMul4",
            &["{{any::m}} never be match", "{{number::m}} could be match"],
            &["-a", "-r"],
        ),
        ("psudoMulAny", &["{{any::m}}"], &["-a", "-r"]),
        (
            "psudoMulPath",
            &[
                "{{text::m}} {{anypath::m}}",
                "{{path::om}}",
                "{{anypath::om}}",
            ],
            &["-a", "-r"],
        ),
        // dropped: "{{{invalid}}}{{port::om}}", "{{digit::om}}{{{invalid}}}"
        (
            "psudoInvalid",
            &["{{port}} {{anypath::om}}", "{{name::om}} {{port}}"],
            &[],
        ),
        ("ip", &[""], &["a", "r"]),
        ("kport", &["{{name}} {{{|grep}}} {{port}}"], &[]),
        (
            "iftopcmd",
            &[
                "-s {{number:seconds}} -i {{name:interface}} -L {{number:line_number}}",
                "-s {{number:seconds}} -i {{name:interface}}",
            ],
            &[],
        ),
        (
            "rsync",
            &[
                r"-Cauvz /data/$(date +\\%Y\\%m\\%d).csv {{name}}:/opt/data",
                "-Cauvz /data/book {{name}}:/data",
            ],
            &[],
        ),
        (
            "yum",
            &["list installed", "install {{name::m}}", "remove {{name}}"],
            &["-y"],
        ),
        (
            "awk",
            &[
                r#"{{{-F,}}} {{{'$1}}} {{{>=}}} {{{"}}}{{datetime}}{{{"}}} {{{&&}}} {{{$1}}} {{{<=}}} {{{"}}}{{datetime:TIME}}{{{"'}}} {{{/opt/operation/record.csv}}}"#,
            ],
            &[],
        ),
        ("w", &[], &[]),
        ("uname", &[], &["-a"]),
        // dropped: "invalid {{invalid}}"
        ("custom", &["{{custom}}"], &[]),
        ("custom3", &["{{custom}}test"], &[]),
        ("custom2", &["{{custom::om}}"], &[]),
        ("ps", &[""], &["-ef", "x", "-aux"]),
        (
            "netstat",
            &[
                "-tunlp|grep {{name}}",
                "-tunp|grep {{name}}",
                "| grep {{name}}",
                "",
            ],
            &["-tunlp", "-tunp"],
        ),
    ];
    specs
        .iter()
        .map(|(name, args, opts)| (*name, Command::new(args, opts, &registry).unwrap()))
        .collect()
}

#[test]
fn rejected_templates() {
    // A custom type named "" would let `{{:A:}}` resolve to it, so it can't be registered.
    for name in ["", "a b", "a:b", "{x}"] {
        assert!(
            matches!(Registry::new([], [(name, "x")]), Err(RegistryError::InvalidName(n)) if n == name),
            "custom type name {name:?} should be rejected"
        );
    }
    let registry = Registry::new([], [("custom", "custom[0-9]+")]).unwrap();
    for bad in [
        "/etc/{{text:MSG:o}}",
        "foo{{anypath:ANY}}",
        "{{:A:}}",
        "{{{test}}}{{number:NUM:o}}",
        "{{datetime::o}}-00:00",
        "{{{invalid}}}{{port::om}}",
        "{{digit::om}}{{{invalid}}}",
        "invalid {{invalid}}",
    ] {
        assert!(
            Command::new(&[bad], &[], &registry).is_err(),
            "{bad} should not compile"
        );
    }
}

/// (command, line, Some((args, template)) if allowed)
type Case = (
    &'static str,
    &'static str,
    Option<(&'static str, &'static str)>,
);

const CASES: &[Case] = &[
    (
        "vpninfo",
        "vpninfo -s 12345",
        Some(("-s 12345", "-s {{name}}")),
    ),
    ("vpninfo", "vpninfo --s server", None),
    ("w", "w", Some(("", ""))),
    ("psudocmd", "psudocmd server2v -c", None),
    (
        "psudocmd",
        "psudocmd hello{world}",
        Some(("hello{world}", "{{name}}{world}")),
    ),
    (
        "invalid",
        r#"invalid "" name"#,
        Some((r#""" name"#, r#""" {{name}}"#)),
    ),
    // CHANGED: `{{name:have space}}` is now valid, and `80` is a name.
    ("invalid", "invalid 80", Some(("80", "{{name:have space}}"))),
    // CHANGED: descriptions may contain spaces, so `{{name:have space}}` is a valid template.
    (
        "invalid",
        "invalid arg1",
        Some(("arg1", "{{name:have space}}")),
    ),
    (
        "psudocmd",
        "psudocmd server1 -c",
        Some(("server1v -c", "server{{number}}{{{v}}} -c")),
    ),
    (
        "tcping",
        "tcping 10.123.2.3:22",
        Some(("10.123.2.3:22", "{{ipv4:IP}}:{{port:PORT}}")),
    ),
    (
        "psudocmd",
        "psudocmd foodir",
        Some(("foobardir", "foo{{{bar}}}dir")),
    ),
    (
        "psudocmd",
        "psudocmd mathA-1 '积分'",
        Some((
            "/book mathA-1 '积分'",
            "{{{/book}}} math{{alpha:A-Z}}-{{digit:0-9}} {{text}}",
        )),
    ),
    (
        "psudoMul",
        r#"psudoMul   'hello      world'    "11 22  33"     'peace and love' "你好！   世界"    "#,
        Some((
            r#"'hello      world' "11 22  33" 'peace and love' "你好！   世界""#,
            "{{text::m}}",
        )),
    ),
    ("psudoMul2", "psudoMul2 -a -r", Some(("-a -r", ""))),
    ("psudoMul2", "psudoMul2 -a", Some(("-a", ""))),
    ("psudoMul2", "psudoMul2 80 arg1 arg2  18:00:00", None),
    // CHANGED: Go let {{number::m}} take the prefix `18` of `18:00:00` and then failed.
    // Here a repeated slot only takes whole words, so it stops and {{datetime}} matches.
    (
        "psudoMul2",
        "psudoMul2 80 443 18:00:00",
        Some((
            "80 443 18:00:00",
            "{{port}} {{number::m}} {{name::o}} {{datetime}}",
        )),
    ),
    (
        "psudoMul2",
        "psudoMul2 80 443 arg2  18:00:00",
        Some((
            "80 443 arg2 18:00:00",
            "{{port}} {{number::m}} {{name::o}} {{datetime}}",
        )),
    ),
    ("psudoMul2", "psudoMul2 80 443 arg1 arg2  18:00:00", None),
    (
        "psudoMul2",
        "psudoMul2 80 123 123    123   arg1 arg2",
        Some((
            "80 123 123 123 arg1 arg2",
            "{{port}} {{number::m}} {{name::o}} {{name}}",
        )),
    ),
    ("psudoMul2", "psudoMul2 80 123 123    123   20240102", None),
    ("psudoMul2", "psudoMul2 80 123 123    123   ", None),
    (
        "psudoMul3",
        "psudoMul3 'a' 'b' 1 2 3 ab 123 abc 123",
        Some((
            "'a' 'b' 1 2 3 ab 123 abc 123",
            "{{text::om}} {{number::om}} {{alpha::om}} {{name::om}}",
        )),
    ),
    // CHANGED: same prefix issue as above; `999999abc` is a valid {{name}}.
    (
        "psudoMul3",
        "psudoMul3 'a' 'b' 999999abc 123",
        Some((
            "'a' 'b' 999999abc 123",
            "{{text::om}} {{number::om}} {{alpha::om}} {{name::om}}",
        )),
    ),
    (
        "psudoMul3",
        "psudoMul3 'a' 'b' abc 123",
        Some((
            "'a' 'b' abc 123",
            "{{text::om}} {{number::om}} {{alpha::om}} {{name::om}}",
        )),
    ),
    ("psudoMul3", "psudoMul3 'a' 123 'b'", None),
    (
        "psudoMul3",
        "psudoMul3",
        Some(("", "{{text::om}} {{number::om}} {{alpha::om}} {{name::om}}")),
    ),
    ("psudoMul4", "psudoMul4  could   be match", None),
    (
        "psudoMul4",
        "psudoMul4 1 2 3 could   be match",
        Some(("1 2 3 could be match", "{{number::m}} could be match")),
    ),
    ("psudoMul4", "psudoMul4 a b c d never be match", None),
    ("psudoMul", "psudoMul 80 8088  a 443  8086", None),
    (
        "psudoMul",
        "psudoMul 80 8088    443  8086",
        Some(("80 8088 443 8086", "{{port::om}}")),
    ),
    (
        "psudoMul",
        "psudoMul  80      end",
        Some(("80 end", "{{port}} {{datetime::om}} {{ipv4::om}} end")),
    ),
    (
        "psudoMul",
        "psudoMul  80     10.1.1.1 2.2.2.2  end",
        Some((
            "80 10.1.1.1 2.2.2.2 end",
            "{{port}} {{datetime::om}} {{ipv4::om}} end",
        )),
    ),
    (
        "psudoMul",
        "psudoMul  80  17:00:00  18:00:00 19:00:00  10.1.1.1    3.3.3.3 2.2.2.2  end",
        Some((
            "80 17:00:00 18:00:00 19:00:00 10.1.1.1 3.3.3.3 2.2.2.2 end",
            "{{port}} {{datetime::om}} {{ipv4::om}} end",
        )),
    ),
    ("psudoMul", "psudoMul", Some(("", "{{port::om}}"))),
    ("psudoMulPath", "psudoMulPath", Some(("", "{{path::om}}"))),
    ("psudoMulPath", "psudoMulPath 'aaaaaaaa' ", None),
    (
        "psudoMulPath",
        "psudoMulPath 'a' 'b  c' ' d' -r /var/db /home/test    /opt/rh/gcc-toolset-13",
        Some((
            "'a' 'b  c' ' d' -r /var/db /home/test /opt/rh/gcc-toolset-13",
            "{{text::m}} {{anypath::m}}",
        )),
    ),
    (
        "psudoMulPath",
        "psudoMulPath /var/db /home/test    /opt/rh/gcc-toolset-13",
        Some((
            "/var/db /home/test /opt/rh/gcc-toolset-13",
            "{{anypath::om}}",
        )),
    ),
    (
        "psudoMulPath",
        "psudoMulPath group passwd fstab",
        Some(("group passwd fstab", "{{path::om}}")),
    ),
    (
        "iftopcmd",
        "iftopcmd -s 10 -i eno1",
        Some((
            "-s 10 -i eno1",
            "-s {{number:seconds}} -i {{name:interface}}",
        )),
    ),
    (
        "iftopcmd",
        "iftopcmd -s 10 -i eno1 -L 20",
        Some((
            "-s 10 -i eno1 -L 20",
            "-s {{number:seconds}} -i {{name:interface}} -L {{number:line_number}}",
        )),
    ),
    ("psudoMulAny", "psudoMulAny", None),
    // CHANGED: `-r` given twice; each option may be used once.
    (
        "psudoMulAny",
        "psudoMulAny -r -a a   b r  c   d   e      f -r",
        None,
    ),
    (
        "psudoMulAny",
        "psudoMulAny -r -a a   b r  c   d   e      f",
        Some(("-r -a a b r c d e f", "{{any::m}}")),
    ),
    (
        "psudoMulAny",
        "psudoMulAny a  -a  b -r  c   d   e      f",
        None,
    ),
    ("psudoInvalid", "psudoInvalid /etc/arg1 80 arg3 80", None),
    ("psudoInvalid", "psudoInvalid arg1 arg2 arg3 80", None),
    ("psudoInvalid", "psudoInvalid 80000", None),
    ("psudocmd", "psudocmd math-1 '积分'", None),
    (
        "awk",
        "awk 2021-01-03 2021-01-09",
        Some((
            r#"-F, '$1 >= "2021-01-03" && $1 <= "2021-01-09"' /opt/operation/record.csv"#,
            r#"{{{-F,}}} {{{'$1}}} {{{>=}}} {{{"}}}{{datetime}}{{{"}}} {{{&&}}} {{{$1}}} {{{<=}}} {{{"}}}{{datetime:TIME}}{{{"'}}} {{{/opt/operation/record.csv}}}"#,
        )),
    ),
    (
        "kport",
        "kport   nginx 443",
        Some(("nginx |grep 443", "{{name}} {{{|grep}}} {{port}}")),
    ),
    (
        "date",
        "date '+%Y%m%d %H:%M:%S'",
        Some(("'+%Y%m%d %H:%M:%S'", "'+%Y%m%d %H:%M:%S'")),
    ),
    ("date", "date '+%s'", Some(("'+%s'", "'+%s'"))),
    (
        "cat",
        "cat /opt/foo/data",
        Some(("/opt/foo/data", "/opt/{{name}}/data")),
    ),
    ("ls", "ls -l $HOME/john", None),
    (
        "grep",
        r#"  grep   "default 0 0"   /etc/fstab  "#,
        Some((
            r#""default 0 0" /etc/fstab"#,
            "{{text:PATTERN}} {{path:FILE:o}}",
        )),
    ),
    ("curl", "curl 192.168.255.255:83333", None),
    ("psudoOpt", "psudoOpt 'hello'   -k     'world'", None),
    (
        "psudoOpt",
        "psudoOpt 'hello' ",
        Some(("'hello'", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    ("psudoOpt2", "psudoOpt2 'hello' world", None),
    ("psudoOpt2", "psudoOpt2 name name", None),
    (
        "psudoOpt",
        "psudoOpt name name name",
        Some((
            "name name name",
            "{{name}} {{number::o}} {{number::o}} {{name::o}} {{name}}",
        )),
    ),
    ("psudoOpt", "psudoOpt name 10000 name", None),
    (
        "psudoOpt",
        "psudoOpt -k   ",
        Some(("-k", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    (
        "psudoOpt",
        "psudoOpt   anything",
        Some(("anything", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    (
        "psudoOpt",
        "psudoOpt  /var/log/lastlog anything",
        Some((
            "/var/log/lastlog anything",
            "{{text::o}} {{anypath::o}} {{any::o}}",
        )),
    ),
    (
        "psudoOpt",
        "psudoOpt -k 'hello' /var/log/lastlog anything",
        Some((
            "-k 'hello' /var/log/lastlog anything",
            "{{text::o}} {{anypath::o}} {{any::o}}",
        )),
    ),
    ("psudoOpt2", "psudoOpt2 name ", None),
    ("psudoOpt2", "psudoOpt2 name 10000 ", None),
    (
        "psudoOpt",
        "psudoOpt name 10000 ",
        Some(("name 10000", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    ("psudoOpt", "psudoOpt name name '10000'", None),
    (
        "psudoOpt",
        "psudoOpt 10000 10000",
        Some(("10000 10000", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    (
        "psudoOpt",
        "psudoOpt 10000 fstab ",
        Some(("10000 fstab", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    (
        "psudoOpt",
        "psudoOpt name 10000 name name",
        Some((
            "name 10000 name name",
            "{{name}} {{number::o}} {{number::o}} {{name::o}} {{name}}",
        )),
    ),
    ("psudoOpt2", "psudoOpt2", None),
    ("psudoOpt2", "psudoOpt2 test", None),
    (
        "psudoOpt",
        "psudoOpt 10000   -k",
        Some(("10000 -k", "{{text::o}} {{anypath::o}} {{any::o}}")),
    ),
    (
        "curl",
        "curl 127.0.0.1:80/monitor/process?sort=asc",
        Some((
            "127.0.0.1:80/monitor/process?sort=asc",
            "127.0.0.1:{{number:PORT}}/monitor/process?sort={{name:FIELD}}",
        )),
    ),
    ("curl", "curl 192.168.255.455:3333", None),
    (
        "curl",
        "curl 192.168.255.255:3333",
        Some(("192.168.255.255:3333", "{{ipv4}}:{{port}}")),
    ),
    ("ls", "ls fstab", Some(("fstab", "{{anypath:PATH}}"))),
    ("echo", "echo /etc/fstab.txt", None),
    (
        "echo",
        r#"echo "hello world!""#,
        Some((r#""hello world!""#, "{{text:MSG:o}}")),
    ),
    (
        "ansible-playbook",
        "ansible-playbook /home/test/playbook/test.yml -k",
        Some((
            "/home/test/playbook/test.yml -k",
            "/home/test/playbook/{{name:PATH}} -k",
        )),
    ),
    (
        "ansible-playbook",
        "ansible-playbook /home/test/playbook/foo/test.yml -k",
        Some((
            "/home/test/playbook/foo/test.yml -k",
            "/home/test/playbook/{{name:PATH}}/{{name:PATH}} -k",
        )),
    ),
    (
        "ansible-playbook",
        "ansible-playbook /home/test/playbook/foo/bar/test.yml -k",
        None,
    ),
    (
        "ansible-playbook",
        "ansible-playbook /bar/test.yml   -k",
        Some((
            "/opt/foo/playbook/bar/test.yml -k",
            "{{{/opt/foo/playbook}}}/{{name:PATH}}/{{name:PATH}} -k",
        )),
    ),
    (
        "echo",
        "echo 'hello world!'",
        Some(("'hello world!'", "{{text:MSG:o}}")),
    ),
    ("echo", r#"echo hello world!""#, None),
    ("echo", "echo 'hello world!", None),
    ("echo", "echo 'hello' world!", None),
    ("cat", "cat test.txt", Some(("test.txt", "{{name}}"))),
    ("cat", "cat /opt/foo/data2", None),
    ("psudocmd", r#"psudocmd "start""#, None),
    // CHANGED: `{{text}}` may now be glued to literals.
    (
        "psudocmd",
        r#"psudocmd "start"end"#,
        Some((r#""start"end"#, "{{text}}end")),
    ),
    ("psudocmd", "psudocmd /etc/f,stab", None),
    (
        "psudocmd",
        "psudocmd /etc/fstab",
        Some((
            "/home/test/etc/fstab",
            "{{{/home}}}{{{/test}}}/{{name}}/{{name}}",
        )),
    ),
    ("psudocmd", "psudocmd /home/test/etc/fstab", None),
    ("cat", "cat test,csv", None),
    ("cat", "cat /opt/999/data/", None),
    (
        "cat",
        "cat /opt/1/foo/test.csv",
        Some(("/opt/1/foo/test.csv", "/opt/{{number}}/foo/{{name}}")),
    ),
    ("echo", "echo /etc/'hello world!'", None),
    ("echo", "echo /etc/", None),
    ("echo", "echo /etc/hello.txt", None),
    ("echo", "echo /etchellotxt", None),
    ("echo", "echo", Some(("", "{{text:MSG:o}}"))),
    (
        "echo",
        "echo 'hello' test",
        Some(("'hello' test", "{{text:MSG}} test")),
    ),
    ("echo", "echo '$(date) hello world!'", None),
    (
        "rsync",
        r"rsync -Cauvz /data/$(date +\\%Y\\%m\\%d).csv server:/opt/data",
        Some((
            r"-Cauvz /data/$(date +\\%Y\\%m\\%d).csv server:/opt/data",
            r"-Cauvz /data/$(date +\\%Y\\%m\\%d).csv {{name}}:/opt/data",
        )),
    ),
    ("rsync", "rsync -Cauvz /data/img server:/data", None),
    (
        "rsync",
        "rsync -Cauvz /data/book server:/data",
        Some((
            "-Cauvz /data/book server:/data",
            "-Cauvz /data/book {{name}}:/data",
        )),
    ),
    ("rsync", "rsync -Cauvz /data/book server:/data/abc", None),
    (
        "grep",
        r#"  grep   "default 0 0"   passwd "#,
        Some((
            r#""default 0 0" passwd"#,
            "{{text:PATTERN}} {{path:FILE:o}}",
        )),
    ),
    ("grep", r#"  grep   "default 0 0"   shadow "#, None),
    ("grep", "  grep   UUID  /etc/fstab  ", None),
    ("dmesg", "dmesg -h", Some(("-h", ""))),
    ("ip", "ip a", Some(("a", ""))),
    ("ip", "ip route r", None),
    ("ip", "ip a r", Some(("a r", ""))),
    (
        "telnet",
        "telnet    192.1.3.254   333",
        Some(("192.1.3.254 333", "{{ipv4}} {{port}}")),
    ),
    ("telnet", "telnet    192.1.3.2:   333", None),
    (
        "telnet",
        "telnet    192.1.3.2   333",
        Some(("192.1.3.2 333", "{{ipv4}} {{port}}")),
    ),
    // CHANGED: the Go suite marked accepting this as a BUG.
    ("yum", "yum   install -y tmux -y", None),
    // New: `$` and `\` are live inside double quotes once the line reaches a shell.
    ("echo", r#"echo "$HOME""#, None),
    ("echo", r#"echo "a\""#, None),
    ("echo", "echo '$HOME'", Some(("'$HOME'", "{{text:MSG:o}}"))),
    (
        "yum",
        "yum   install tmux vim  rsync",
        Some(("install tmux vim rsync", "install {{name::m}}")),
    ),
    (
        "yum",
        "yum   install tmux -y",
        Some(("install tmux -y", "install {{name::m}}")),
    ),
    (
        "custom3",
        "custom3 custom2test",
        Some(("custom2test", "{{custom}}test")),
    ),
    ("custom2", "custom2 custom1 custom2 custom3 123", None),
    (
        "custom2",
        "custom2 custom1 custom2 custom3",
        Some(("custom1 custom2 custom3", "{{custom::om}}")),
    ),
    (
        "custom2",
        "custom2 custom1",
        Some(("custom1", "{{custom::om}}")),
    ),
    ("custom2", "custom2", Some(("", "{{custom::om}}"))),
    ("custom", "custom custom1", Some(("custom1", "{{custom}}"))),
    ("custom", "custom 123456", None),
    ("custom", "custom invalid 123456", None),
    (
        "yum",
        "yum list  installed",
        Some(("list installed", "list installed")),
    ),
    (
        "yum",
        "yum remove wget",
        Some(("remove wget", "remove {{name}}")),
    ),
    ("ls", "ls -k /etc/fstab", None),
    (
        "ls",
        "ls -lh /etc/fstab",
        Some(("-lh /etc/fstab", "{{anypath:PATH}}")),
    ),
    (
        "ls",
        "ls  /etc/fstab   -lh",
        Some(("/etc/fstab -lh", "{{anypath:PATH}}")),
    ),
    ("ls", "ls -c", None),
    ("ps", "ps", Some(("", ""))),
    ("ps", "ps -ef", Some(("-ef", ""))),
    ("ps", "ps -a", None),
    ("netstat", "netstat -anp", None),
    ("netstat", "netstat", Some(("", ""))),
    ("w", "w -l", None),
    ("netstat", "netstat -tunp", Some(("-tunp", ""))),
    ("netstat", "netstat -tunp |grep 22", None),
    (
        "netstat",
        "netstat -tunp|grep 22",
        Some(("-tunp|grep 22", "-tunp|grep {{name}}")),
    ),
    ("uname", "uname ", Some(("", ""))),
    ("uname", "uname -a", None),
    ("dmidecode", "dmidecode -t memory cpu", None),
    ("dmidecode", "dmidecode ", None),
    ("dmidecode", "dmidecode -t", Some(("-t", "-t"))),
];

#[test]
fn verify_args() {
    let commands = commands();
    let mut failures = Vec::new();
    for (i, &(cmd, line, expect)) in CASES.iter().enumerate() {
        let got = split_words(line).ok().and_then(|words| {
            commands[cmd]
                .verify(&words[1..], "/etc")
                .map(|v| (v.args, v.template.to_owned()))
        });
        let expect = expect.map(|(a, t)| (a.to_owned(), t.to_owned()));
        if got != expect {
            failures.push(format!(
                "case {i}: `{line}`\n  got:    {got:?}\n  expect: {expect:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
