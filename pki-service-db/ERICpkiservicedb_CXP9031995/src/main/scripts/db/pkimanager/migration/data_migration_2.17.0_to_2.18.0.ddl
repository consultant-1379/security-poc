UPDATE entityprofile SET subject_unique_identifier_value = '?' WHERE name = 'AMOS_EM_USER_EP';
UPDATE entity SET subject_unique_identifier_value = entity.name WHERE entity_profile_id = (SELECT id FROM entityprofile WHERE name ='AMOS_EM_USER_EP');

