from app.static_analysis.yara_scanner import get_rules
m = get_rules().match(data=b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
for x in m:
    print(x.rule, x.meta)
    