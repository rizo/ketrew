(**************************************************************************)
(*  Copyright 2015, Sebastien Mondet <seb@mondet.org>                     *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

open Ketrew_pervasives
module Path = Ketrew_path
module Host = Ketrew_host
module Program = Ketrew_program

module Volume = struct

  type structure = [
    | `File of string
    | `Directory of (string * structure list)
  ] [@@deriving yojson]

  type t = {
    host: Host.t;
    root: Path.t;
    structure: structure;
  } [@@deriving yojson]
  let create ~host ~root structure = {host; root; structure}
  let file s = `File s
  let dir name contents = `Directory (name, contents)

  let rec all_structure_paths = fun s ->
    match s with
    | `File s -> [Path.relative_file_exn s ]
    | `Directory (name, children) ->
      let children_paths = 
        List.concat_map ~f:all_structure_paths children in
      let this_one = Path.relative_directory_exn name in
      this_one :: List.map ~f:(Path.concat this_one) children_paths

  let all_paths t: Path.t list =
    List.map ~f:(Path.concat t.root) (all_structure_paths t.structure)

  let log_structure structure = 
    let all_paths = all_structure_paths structure |> List.map ~f:Path.to_string in
    let open Log in
    match all_paths with
    | [] -> s "EMPTY"
    | one :: [] -> s "Single path: " % quote one
    | more -> i (List.length more) % sp % s "paths"

  let log {host; root; structure} =
    Log.(braces (
        parens (Ketrew_host.log host) % sp
        % parens (s "Root: " % s (Path.to_string root)) % sp
        % parens (s "Tree: " % log_structure structure)
      ))

  let to_string_hum v =
    Log.to_long_string (log v)

end

type id = Unique_id.t
[@@deriving yojson]

module Command = struct

  type t = {
    host: Host.t;
    action: Program.t;
  } [@@deriving yojson]
  let shell ?(host=Host.tmp_on_localhost) s = { host; action = `Shell_command s}
  let program ?(host=Host.tmp_on_localhost) action = { host; action}

  let get_host t = t.host

  let log {host; action} = 
    Log.(s "Action: " % Program.log action
         % s " on " % s (Host.to_string_hum host))

  let to_string_hum c = Log.to_long_string (log c)

end

module Condition = struct
  type t = [
    | `Satisfied
    | `Never
    | `Volume_exists of Volume.t
    | `Volume_size_bigger_than of (Volume.t * int)
    | `Command_returns of (Command.t * int)
    | `And of t list
  ] [@@deriving yojson]
  let rec log =
    Log.(function
      | `Satisfied -> s "Satisfied"
      | `Never -> s "Never"
      | `Volume_exists v -> 
        parens (s "Volume " % Volume.log v % s " exists")
      | `Volume_size_bigger_than (v, sz) ->
        parens (s "Volume " % Volume.log v % s " ≥ " 
                % i sz % nbsp % s "B")
      | `Command_returns (c, ret) ->
        parens (s "Command " % Command.log c % s " returns " % i ret)
      | `And l ->
        parens (separate (s " && ") (List.map l ~f:log))
      )
  let to_string_hum c = Log.to_long_string (log c)
end

module Build_process = struct
  type t = [
    | `No_operation
    | `Long_running of (string * string)
  ] [@@deriving yojson]

  let nop : t = `No_operation
end



module Equivalence = struct
  type t = [
    | `None
    | `Same_active_condition
  ] [@@deriving yojson]
end

type t = {
  id: id;
  name: string;
  metadata: [`String of string] option;
  dependencies: id list;
  if_fails_activate: id list;
  success_triggers: id list;
  make: Build_process.t;
  condition: Condition.t option;
  equivalence: Equivalence.t;
  (* history: State.t; *)
  log: (Time.t * string) list;
  tags: string list;
  user_activated: bool;
} [@@deriving yojson]

let create
    ?id ?name ?metadata
    ?(dependencies=[]) ?(if_fails_activate=[]) ?(success_triggers=[])
    ?(make=Build_process.nop)
    ?condition ?(equivalence=`Same_active_condition) ?(tags=[])
    ?(active=false)
    () = 
  let id = Option.value id ~default:(Unique_id.create ()) in
  { id; name = Option.value name ~default:id; metadata; tags; 
    log = []; dependencies; make; condition; equivalence;
    if_fails_activate; success_triggers; user_activated = active}

let to_serializable t = t
let of_serializable t = t

let id : t -> Unique_id.t = fun t -> t.id
let name : t -> string = fun t -> t.name
let dependencies: t -> id list = fun t -> t.dependencies
let fallbacks: t -> id list = fun t -> t.if_fails_activate
let success_triggers: t -> id list = fun t -> t.success_triggers
let metadata = fun t -> t.metadata
let build_process: t -> Build_process.t = fun t -> t.make
let condition: t -> Condition.t option = fun t -> t.condition
let equivalence: t -> Equivalence.t = fun t -> t.equivalence
let additional_log: t -> (Time.t * string) list = fun t -> t.log
let tags: t -> string list = fun t -> t.tags
(* let state: t -> State.t = fun t -> t.history *)

let is_equivalent t ext =
  match t.equivalence with
  | `None -> false
  | `Same_active_condition -> 
    begin match t.condition with
    | None -> false
    | Some other -> Some other = ext.condition
    end


let log t = Log.(brakets (sf "Target: %s (%s)" t.name t.id))


module Target_pointer = struct
  type target = t [@@deriving yojson]
  type t = {
    original: target;
    pointer: id;
  } [@@deriving yojson]

end

module Stored_target = struct
  type target = t [@@deriving yojson]

  module V0 = struct
    type t = [
      | `Target of target
      | `Pointer of Target_pointer.t
    ] [@@deriving yojson]
  end
  include Json.Versioned.Of_v0(V0)
  type t = V0.t

  let deserialize s : (t, _) Result.t =
    let open Result in
    begin
      try return (deserialize_exn s)
    with e -> fail (`Target (`Deserilization (Printexc.to_string e)))
    end

  let get_target = function
  | `Target t -> `Target t
  | `Pointer { Target_pointer. pointer; _} -> `Pointer pointer

  let of_target t = `Target t

  let id = function
  | `Target t -> t.id
  | `Pointer { Target_pointer. original } -> original.id

  let make_pointer ~from ~pointing_to =
    `Pointer { Target_pointer.
               original = from;
               pointer = pointing_to.id }
end
