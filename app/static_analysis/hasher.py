import hashlib


def get_hashes(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0

    with open(file_path, "rb") as f:          # "rb" = read the raw bytes
        while True:
            chunk = f.read(1024 * 1024)       # read 1 MB at a time
            if not chunk:                     # empty = end of file
                break
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": size,
    }