"""Fail-closed exact-function replacement across pinned TI NPI/AF source paths."""
import hashlib
from pathlib import Path

def replace_in_path_function(sdk, path, signature, substitutions, changes):
    p=Path(sdk)/path
    old=p.read_text()
    if old.count(signature)!=1:
        raise ValueError(f"Expected one complete function signature in {path}: {signature[:75]}")
    start=old.index(signature)
    brace=old.index("{",start+len(signature)-1)
    depth=0;stop=None
    for pos in range(brace,len(old)):
        if old[pos]=="{":depth+=1
        elif old[pos]=="}":
            depth-=1
            if depth==0:
                stop=pos+1
                break
    if stop is None:raise ValueError("Unbalanced source function in "+path)
    body=old[start:stop]
    for before,after in substitutions:
        n=body.count(before)
        if n!=1:
            raise ValueError(f"Expected one scoped anchor in {path} {signature}: count={n} {before[:85]}")
        body=body.replace(before,after,1)
    new=old[:start]+body+old[stop:]
    p.write_text(new)
    changes.append({"path":path,
                    "before_sha256":hashlib.sha256(old.encode()).hexdigest(),
                    "after_sha256":hashlib.sha256(new.encode()).hexdigest()})
