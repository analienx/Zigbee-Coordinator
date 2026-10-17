#!/usr/bin/env python3
"""Attribute linked Zigbee routing functions to their actual TI object inputs.

Reads genuine B0 ELF/XML validated separately by b0_image_audit.py. A library
path is NOT proof that TI has published a modifiable C source body.
"""
import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from b2_collect_native_evidence import EvidenceError, load_manifest, parse_elf

API = ("RTG_GetRtgSrcEntry", "RTG_ProcessRErr", "RTG_SrcGetNextHop",
       "RTG_ProcessRreq", "RTG_ProcessRrep", "RTG_MTORouteReq",
       "RTG_Init", "RTG_AddSrcRtgEntry_Guaranteed",
       "RTG_RouteMaintanence", "RTG_SendBrokenRoute",
       "nwkHandleBrokenRoute")

def audit(root_path, out_path):
    files=load_manifest(root_path)
    parse_elf(files["elf"]["path"])
    raw=files["xml"]["path"].read_bytes()
    if len(raw)>2*1024*1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise EvidenceError("XML length/entity violation")
    root=ET.fromstring(raw)
    if root.tag!="link_info":
        raise EvidenceError("not TI linker XML")
    by_id = lambda query, attribute: {
        el.attrib[attribute]:el for el in root.findall(query)
        if attribute in el.attrib}
    input_files=by_id("./input_file_list/input_file","id")
    objects=by_id("./object_component_list/object_component","id")
    symbols={}
    for el in root.findall("./symbol_table/symbol"):
        name=el.findtext("name")
        if name not in API:
            continue
        refs=el.findall("object_component_ref")
        if len(refs)!=1:
            symbols[name]={"status":"AMBIGUOUS_OR_MISSING_OBJECT_REF"}
            continue
        obj=objects.get(refs[0].get("idref"))
        if obj is None:
            symbols[name]={"status":"MISSING_OBJECT_COMPONENT"}
            continue
        oref=obj.find("input_file_ref")
        fil=input_files.get(oref.get("idref")) if oref is not None else None
        if fil is None:
            symbols[name]={"status":"MISSING_INPUT_FILE"}
            continue
        symbols[name]={
            "status":"LINKED_OBJECT_ORIGIN",
            "archive_file":fil.findtext("file"),
            "archive_member_object":fil.findtext("name"),
            "object_input_path":fil.findtext("path"),
            "object_kind":fil.findtext("kind"),
            "object_component_name":obj.findtext("name"),
            "linker_symbol_value":el.findtext("value"),
            "input_file_ref":oref.get("idref"),
        }
    for name in API:
        if name not in symbols:
            symbols[name]={"status":"NOT_IN_LINKER_XML_MAY_BE_STRIPPED_OR_INLINED"}
    data={"status":"HOSTED_NATIVE_OBJECT_ATTRIBUTION","artifact_elf_sha256":files["elf"]["sha256"],
          "artifact_xml_sha256":files["xml"]["sha256"],
          "scope":"B0 reference only; no C-source body claim, no firmware modifications",
          "symbols":symbols}
    out_path.mkdir(parents=True,exist_ok=True)
    (out_path/"B2_ROUTING_OBJECT_ORIGINS.json").write_text(
        json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    lines=[
        "# TI B0 routing object provenance — real linker evidence",
        "",
        "Compiled routing functions are attributed using the actual TI linker XML",
        "symbol -> object_component -> input_file references. This does not prove",
        "C source availability or safe binary modification.",
        "",
        "| Routine | Linked object | Kind | Provenance |",
        "| --- | --- | --- | --- |",
    ]
    for key,item in symbols.items():
        lines.append("| \`"+key+"\` | "+
                     ("\`"+str(item.get("archive_file","UNKNOWN"))+"::"+str(item.get("archive_member_object","UNKNOWN"))+"\`")+" | "+
                     str(item.get("status"))+" | "+
                     ("\`"+str(item.get("object_input_path","UNKNOWN"))+"\`")+" |")
    lines.extend(["","**Decision:** B2 may configure source-owned table declarations and",
                  "test externally visible behavior. Do not invent RTG C patches",
                  "or claim source-compiled internal routing-body tests unless those",
                  "bodies are independently obtained and vetted. No proprietary",
                  "binary patching/reverse engineering is proposed.",
                  ""])
    (out_path/"ROUTING_OBJECT_PROVENANCE.md").write_text(
        "\n".join(lines),encoding="utf-8")
    return data

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--artifacts",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    result=audit(a.artifacts,a.out)
    print(json.dumps({"result":result["status"],
                      "attributed":sum(v["status"]=="LINKED_OBJECT_ORIGIN"
                            for v in result["symbols"].values())}))
if __name__=="__main__":
    main()
