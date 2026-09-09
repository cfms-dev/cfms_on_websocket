Added an optional `scheduled_lockdown` task for recurring or one-time, fixed-duration
lockdown windows. The scheduling core now supports state-dependent system schedules
whose factories can retire their persisted schedule by returning `None`.
