SELECT add_column_if_not_exists('entity', 'otp_generated_time', 'ALTER TABLE IF EXISTS entity ADD COLUMN otp_generated_time timestamp default current_timestamp');
SELECT add_column_if_not_exists('entity','otp_validity_period','ALTER TABLE IF EXISTS entity ADD COLUMN otp_validity_period integer default -1');
