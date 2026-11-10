# common.py - helpers shared by every analyzer, so the result format lives in one place.
# Return (_result, _finding) functions that stamp analyzer_name on what they build.

def make_helpers(analyzer_name):                 
    def _result(status, error=None, data=None, findings=None):          # Build the standard result that scanner.py expects.
        return {"analyzer": analyzer_name, "status": status, "error": error,
                "data": data or {}, "findings": findings or []}

    def _finding(fid, severity, message, **detail):                     # Build one finding (id, severity, message, extra details).
        return {"id": fid, "analyzer": analyzer_name, "severity": severity,
                "message": message, "detail": detail}
    return _result, _finding