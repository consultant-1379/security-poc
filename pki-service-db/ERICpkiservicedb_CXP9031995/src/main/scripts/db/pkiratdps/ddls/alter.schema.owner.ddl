DO $$DECLARE r record;
BEGIN
    FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    LOOP
        EXECUTE 'alter table '|| r.tablename ||' owner to pkiratdpsgrp;';
    END LOOP;
END$$;

DO $$DECLARE r record;
BEGIN
    FOR r IN SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public'
    LOOP
        EXECUTE 'alter sequence '|| r.sequence_name ||' owner to pkiratdpsgrp;';
    END LOOP;
END$$;

DO $$DECLARE r record;
BEGIN
    FOR r IN SELECT nsp.nspname schema_name, p.proname function_name, pg_get_function_identity_arguments(p.oid) function_arguments FROM pg_proc p JOIN pg_namespace nsp ON p.pronamespace = nsp.oid WHERE  nsp.nspname = 'public'
    LOOP
        EXECUTE 'alter function '||r.schema_name||'.'||r.function_name||'('||r.function_arguments||') owner to pkiratdpsgrp;';
    END LOOP;
END$$;