# this repeats character a 19 times then hashes it into a md5
# (v)erbose (b)ruteforce (H)ash (a)lphabet [a, b]
# 8.243s
time cargo run -- -vH ${$(echo -n $(seq -s a 20 | tr -d '[:digit:]') | md5sum)::-1} -ba ab