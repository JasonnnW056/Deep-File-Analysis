import json
from app.analyzer import analyze

print(json.dumps(analyze("abc.txt"), indent=2, default=str))


# -----------------------------------------------------------------------

# import yara
# from app.static_analysis.yara_scanner import get_rules

# data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# matches = get_rules().match(data=data)
# print(matches)