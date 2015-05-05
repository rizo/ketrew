(* OASIS_START *)
(* OASIS_STOP *)
open Ocamlbuild_plugin

(* This file is used by the build system (ocamlbuild specifically) to
   instrument code when we request code coverage. Otherwise it makes no
   changes to the code. *)

let has_coverage () =
  let key = "coverage=" in
  let n   = String.length key in
  try
    let ic = open_in "setup.data" in
    let rec l () =
      let s = input_line ic in
      if String.sub s 0 n = key then
        let sub = String.sub s (n + 1) (String.length s - n - 2) in
        bool_of_string sub
      else
        l ()
    in
    l ()
  with _ -> false

let bisect_dir () =
  let ic = Unix.open_process_in "ocamlfind query bisect_ppx" in
  let line = input_line ic in
  close_in ic;
  line

let () =
  let additional_rules = function
      | After_rules     ->
        if has_coverage () then
          begin
            flag ["compile"]                  (S [A"-package"; A "bisect_ppx"]);
            flag ["link"; "byte"; "program"]  (S [A"-package"; A "bisect_ppx"]);
            flag ["link"; "native"; "program"](S [A"-package"; A "bisect_ppx"]);
          end
        else
          ()
      | _ -> ()
  in
  dispatch
    (MyOCamlbuildBase.dispatch_combine
      [MyOCamlbuildBase.dispatch_default conf package_default;
      additional_rules])
