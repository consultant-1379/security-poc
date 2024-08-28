---- This function kills ongoing transactions on the requested table, to allow database upgrade on time ----
CREATE OR REPLACE FUNCTION kill_ongoing_trans_on_table(upgrading_table text) RETURNS void as $$
DECLARE
   pid INTEGER;
   pid_values INTEGER[];
BEGIN
 SELECT into pid_values array_agg(p1.pid) from pg_locks p1 LEFT JOIN pg_stat_activity psa on p1.pid=psa.pid where p1.relation=(select relid from pg_stat_all_tables where relname=upgrading_table) and p1.pid <> pg_backend_pid();
 IF pid_values IS NOT NULL
 THEN
 FOREACH pid IN ARRAY pid_values
 LOOP
 RAISE LOG 'Transaction with process id % is being killed for upgrading the table %',pid,upgrading_table;
 PERFORM pg_terminate_backend(pid);
 END LOOP;
 END IF;
END;
$$
LANGUAGE plpgsql;

ALTER FUNCTION public.kill_ongoing_trans_on_table(text) owner to pkicoregrp;
