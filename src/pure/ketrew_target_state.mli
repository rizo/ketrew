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

(** Definition of the state of a {!Ketrew_target.t} and implementation
    of the “pure” aspect of the state machine. *)
open Ketrew_pervasives

type t

val create: target:Ketrew_target.id -> unit -> t

module State : sig
  type t
  val simplify: t -> [
      | `Activable
      | `In_progress
      | `Successful
      | `Failed
    ]

  val name: t -> string

  val summary :
    t ->
    [ `Time of Time.t ] * [ `Log of string option ] * [ `Info of string list ]

  val log: ?depth:int ->  t -> Log.t

  (** The date the target's creation. *)
  val passive_time: t -> Time.t

  val finished_time: t -> Time.t option

  module Is : sig
    val building : t -> bool
    val tried_to_start : t -> bool
    val started_running : t -> bool
    val starting : t -> bool
    val still_building : t -> bool
    val still_running : t -> bool
    val ran_successfully : t -> bool
    val successfully_did_nothing : t -> bool
    val active : t -> bool
    val verified_success : t -> bool
    val already_done : t -> bool
    val dependencies_failed : t -> bool
    val failed_running : t -> bool
    val failed_to_kill : t -> bool
    val failed_to_start : t -> bool
    val killing : t -> bool
    val tried_to_kill : t -> bool
    val did_not_ensure_condition : t -> bool
    val killed : t -> bool
    val finished : t -> bool
    val passive : t -> bool
    val killable: t -> bool
    val finished_because_dependencies_died: t -> bool
  end
end

val history: t -> State.t

module Automaton : sig

  (** A {i pure} automaton *)

  type failure_reason
  type progress = [ `Changed_state | `No_change ]
  type 'a transition_callback = ?log:string -> 'a -> t * progress
  type severity = [ `Try_again | `Fatal ]
  (* type 'a io_action = [ `Succeeded of 'a | `Failed of 'a ] *)
  type bookkeeping =
    { plugin_name: string; run_parameters: string}
  type long_running_failure = severity * string * bookkeeping
  type long_running_action =  (bookkeeping, long_running_failure) Pvem.Result.t
  type process_check =
    [ `Successful of bookkeeping | `Still_running of bookkeeping ]
  type process_status_check = (process_check, long_running_failure) Pvem.Result.t
  type condition_evaluation = (bool, severity * string) Pvem.Result.t
  type dependencies_status =
    [ `All_succeeded | `At_least_one_failed of Ketrew_target.id list | `Still_processing ]
  type transition = [
    | `Do_nothing of unit transition_callback
    | `Activate of Ketrew_target.id list * unit transition_callback
    | `Check_and_activate_dependencies of dependencies_status transition_callback
    | `Start_running of bookkeeping * long_running_action transition_callback
    | `Eval_condition of Ketrew_target.Condition.t * condition_evaluation transition_callback
    | `Check_process of bookkeeping * process_status_check transition_callback
    | `Kill of bookkeeping * long_running_action transition_callback
  ]
  val transition: Ketrew_target.t -> t -> transition
end

val activate_exn :
  ?log:string -> t -> reason:[ `Dependency of Ketrew_target.id | `User ] -> t
(** Get an activated target out of a “submitted” one,
    raises [Invalid_argument _] if the target is in a wrong state. *)

val kill : ?log:string -> t -> t option
(** Get dead target out of a killable one,
    or [None] if not killable. *)

val reactivate :
  ?with_id:Ketrew_target.id -> ?with_name:string ->
  ?with_metadata:[`String of string] option  ->
  ?log:string -> t -> t
(** *)

val latest_run_parameters: t -> string option
(** Get the most recent serialized
    [run_parameters] if the target is a “long-running”,
    [None] otherwise. *)
