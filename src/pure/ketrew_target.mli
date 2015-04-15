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

(** Definition of the basic building bloc of a workflow. *)
open Ketrew_pervasives

(** Definition of command-lines to run on a given {!Ketrew_host.t}. *)
module Command : sig

  type t = {
    host: Ketrew_host.t;
    action: Ketrew_program.t;
  }
  (** The type of commands. *)

  val shell : ?host:Ketrew_host.t -> string -> t
  (** Create a “shell” command for a given [Host.t]. *)

  val program: ?host:Ketrew_host.t -> Ketrew_program.t -> t
  (** Create a [Command.t] that runs a {!Ketrew_program.t}. *)

  val get_host : t -> Ketrew_host.t
  (** Get the host. *)

  val log: t -> Log.t
  (** Get a display document. *)

  val to_string_hum : t -> string
  (** Get a Human-readable string. *)

end

module Volume : sig
  type structure =
      [ `Directory of string * structure list | `File of string ]
  type t = { host : Ketrew_host.t; root : Ketrew_path.t; structure : structure; }

  val create : host:Ketrew_host.t -> root:Ketrew_path.t -> structure -> t

  val file : string -> structure
  val dir : string -> structure list -> structure

  val all_paths : t -> Ketrew_path.t list

  val log_structure : structure -> Log.t

  val log : t -> Log.t

  val to_string_hum : t -> string
end

module Build_process: sig
  type t = [
    | `No_operation
    | `Long_running of (string * string)
    (** Use a long-running plugin: [(plugin_name, initial_run_parameters)].  *)
  ]
  (** Specification of how to build a target. {ul
      {li  [`Artifact a]: literal, already-built, artifact, }
      {li [`Direct_command c]: a [Command.t] to run (should produce a [Volume.t]), }
      {li [`Get_output c]: a [Command.t] to run and get its [stdout] (should
       produce a value), }
      {li [`Long_running (plugin_name, initial_run_parameters)]:
      Use a long-running plugin. }
      }
  *)

  val nop : t
  (** A build process that does nothing. *)
end

type id = Unique_id.t [@@deriving yojson]
(** The identifiers of targets. *)

module Condition : sig
  type t = [
    | `Satisfied
    | `Never
    | `Volume_exists of Volume.t
    | `Volume_size_bigger_than of Volume.t * int
    | `Command_returns of Command.t * int
    | `And of t list
  ]
  (**
    An execution anti-condition; the condition defines when a target is
    ready and therefore should be run if the condition is {emph not} met: {ul
    {li with [`Never] the target always runs (because never “ready”),}
    {li with [`Satisfied] the target never runs (a bit useless),}
    {li with [`Volume_exists v] the target runs if the volume does not exist
    ([make]-like behavior).}
    {li with [`Volume_size_bigger_than (v, sz)] Ketrew will get the total size
    of the volume (in bytes) and check that it is bigger.}
    {li with [`Command_returns (c, v)] Ketrew will run the {!Command.t} and
    check its return value.}
    {li [`And list_of_conditions] is a conjunction of conditions.}
      }
  *)

  val log: t -> Log.t
  val to_string_hum: t -> string

end

module Equivalence: sig
  type t = [
    | `None
    | `Same_active_condition
  ]
end

type t
  [@@deriving yojson]
(** The thing holding targets. *)

val create :
  ?id:id -> ?name:string ->
  ?metadata:[ `String of string ] ->
  ?dependencies:id list ->
  ?if_fails_activate:id list ->
  ?success_triggers:id list ->
  ?make:Build_process.t ->
  ?condition:Condition.t ->
  ?equivalence: Equivalence.t ->
  ?tags: string list ->
  ?active: bool ->
  unit ->
  t
(** Create a target value (not stored in the DB yet). *)



val id : t -> Unique_id.t
(** Get a target's id. *)

val name : t -> string
(** Get a target's user-defined name. *)

val dependencies: t -> id list
val fallbacks: t -> id list
val success_triggers: t -> id list
val metadata: t -> [`String of string] option
val build_process: t -> Build_process.t
val condition: t -> Condition.t option
val equivalence: t -> Equivalence.t
val additional_log: t -> (Time.t * string) list
val tags: t -> string list

val is_equivalent: t -> t -> bool
(** Tell whether the first on is equivalent to the second one. This not
    a commutative operation: the function does not look at
    the second target's [Equivalence] field. *)

val log : t -> Log.t
(** Get a [Log.t] “document” to display the target. *)


module Stored_target : sig
  type target = t
  type t
  val to_json: t -> Json.t
  (** Serialize a target to [Json.t] intermediate representation. *)

  val serialize : t -> string
  (** Serialize a target (for the database). *)

  val deserialize :
    string ->
    (t, [> `Target of [> `Deserilization of string ] ])
      Result.t
      (** Deserilize a target from a string. *)

  val get_target: t -> [ `Target of target | `Pointer of id ]
  val of_target: target -> t

  val id: t -> id

  val make_pointer: from:target -> pointing_to:target -> t
end

