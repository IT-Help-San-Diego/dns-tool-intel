-- Table: alembic_version
 column_name |     data_type     | is_nullable | column_default 
-------------+-------------------+-------------+----------------
 version_num | character varying | NO          | 
(1 row)


-- Table: drift_notifications
  column_name   |          data_type          | is_nullable |                 column_default                  
----------------+-----------------------------+-------------+-------------------------------------------------
 id             | integer                     | NO          | nextval('drift_notifications_id_seq'::regclass)
 drift_event_id | integer                     | NO          | 
 endpoint_id    | integer                     | NO          | 
 status         | character varying           | NO          | 'pending'::character varying
 response_code  | integer                     | YES         | 
 response_body  | text                        | YES         | 
 delivered_at   | timestamp without time zone | YES         | 
 created_at     | timestamp without time zone | NO          | now()
(8 rows)


-- Table: icuae_scan_scores
  column_name   |          data_type          | is_nullable |                column_default                 
----------------+-----------------------------+-------------+-----------------------------------------------
 id             | integer                     | NO          | nextval('icuae_scan_scores_id_seq'::regclass)
 domain         | character varying           | YES         | 
 overall_score  | real                        | NO          | 
 overall_grade  | character varying           | NO          | 
 resolver_count | integer                     | NO          | 0
 record_count   | integer                     | NO          | 0
 app_version    | character varying           | YES         | 
 created_at     | timestamp without time zone | NO          | now()
(8 rows)


-- Table: icuae_dimension_scores
      column_name       |     data_type     | is_nullable |                   column_default                   
------------------------+-------------------+-------------+----------------------------------------------------
 id                     | integer           | NO          | nextval('icuae_dimension_scores_id_seq'::regclass)
 scan_id                | integer           | NO          | 
 dimension              | character varying | NO          | 
 score                  | real              | NO          | 
 grade                  | character varying | NO          | 
 record_types_evaluated | integer           | NO          | 0
(6 rows)


-- Table: site_analytics
       column_name       |          data_type          | is_nullable |               column_default               
-------------------------+-----------------------------+-------------+--------------------------------------------
 id                      | integer                     | NO          | nextval('site_analytics_id_seq'::regclass)
 date                    | date                        | NO          | 
 pageviews               | integer                     | NO          | 0
 unique_visitors         | integer                     | NO          | 0
 analyses_run            | integer                     | NO          | 0
 unique_domains_analyzed | integer                     | NO          | 0
 referrer_sources        | jsonb                       | NO          | '{}'::jsonb
 top_pages               | jsonb                       | NO          | '{}'::jsonb
 created_at              | timestamp without time zone | NO          | now()
 updated_at              | timestamp without time zone | NO          | now()
(10 rows)


-- Table: zone_imports
    column_name    |          data_type          | is_nullable |              column_default              
-------------------+-----------------------------+-------------+------------------------------------------
 id                | integer                     | NO          | nextval('zone_imports_id_seq'::regclass)
 user_id           | integer                     | NO          | 
 domain            | character varying           | NO          | 
 sha256_hash       | character varying           | NO          | 
 original_filename | character varying           | NO          | 
 file_size         | integer                     | NO          | 
 record_count      | integer                     | NO          | 0
 retained          | boolean                     | NO          | false
 zone_data         | text                        | YES         | 
 drift_summary     | jsonb                       | YES         | 
 created_at        | timestamp without time zone | NO          | now()
(11 rows)


-- Table: ice_results
 column_name |          data_type          | is_nullable |             column_default              
-------------+-----------------------------+-------------+-----------------------------------------
 id          | integer                     | NO          | nextval('ice_results_id_seq'::regclass)
 run_id      | integer                     | NO          | 
 protocol    | character varying           | NO          | 
 layer       | character varying           | NO          | 
 case_id     | character varying           | NO          | 
 case_name   | character varying           | NO          | ''::character varying
 passed      | boolean                     | NO          | 
 expected    | text                        | YES         | 
 actual      | text                        | YES         | 
 rfc_section | character varying           | YES         | 
 notes       | text                        | YES         | 
 created_at  | timestamp without time zone | NO          | now()
(12 rows)


-- Table: ice_regressions
    column_name    |          data_type          | is_nullable |               column_default                
-------------------+-----------------------------+-------------+---------------------------------------------
 id                | integer                     | NO          | nextval('ice_regressions_id_seq'::regclass)
 protocol          | character varying           | NO          | 
 layer             | character varying           | NO          | 
 run_id            | integer                     | NO          | 
 previous_maturity | character varying           | NO          | 
 new_maturity      | character varying           | NO          | 
 failed_cases      | ARRAY                       | NO          | '{}'::text[]
 notes             | text                        | YES         | 
 created_at        | timestamp without time zone | NO          | now()
(9 rows)


-- Table: domain_analyses
      column_name      |          data_type          | is_nullable |               column_default                
-----------------------+-----------------------------+-------------+---------------------------------------------
 id                    | integer                     | NO          | nextval('domain_analyses_id_seq'::regclass)
 domain                | character varying           | NO          | 
 ascii_domain          | character varying           | NO          | 
 basic_records         | json                        | YES         | 
 authoritative_records | json                        | YES         | 
 spf_status            | character varying           | YES         | 
 spf_records           | json                        | YES         | 
 dmarc_status          | character varying           | YES         | 
 dmarc_policy          | character varying           | YES         | 
 dmarc_records         | json                        | YES         | 
 dkim_status           | character varying           | YES         | 
 dkim_selectors        | json                        | YES         | 
 registrar_name        | character varying           | YES         | 
 registrar_source      | character varying           | YES         | 
 analysis_success      | boolean                     | YES         | 
 error_message         | text                        | YES         | 
 analysis_duration     | double precision            | YES         | 
 created_at            | timestamp without time zone | NO          | 
 updated_at            | timestamp without time zone | YES         | 
 country_code          | character varying           | YES         | 
 country_name          | character varying           | YES         | 
 ct_subdomains         | json                        | YES         | 
 full_results          | json                        | NO          | 
 posture_hash          | character varying           | YES         | 
 private               | boolean                     | NO          | false
 has_user_selectors    | boolean                     | NO          | false
 scan_flag             | boolean                     | NO          | false
 scan_source           | character varying           | YES         | 
 scan_ip               | character varying           | YES         | 
(29 rows)


-- Table: drift_events
   column_name    |          data_type          | is_nullable |              column_default              
------------------+-----------------------------+-------------+------------------------------------------
 id               | integer                     | NO          | nextval('drift_events_id_seq'::regclass)
 domain           | character varying           | NO          | 
 analysis_id      | integer                     | NO          | 
 prev_analysis_id | integer                     | NO          | 
 current_hash     | character varying           | NO          | 
 previous_hash    | character varying           | NO          | 
 diff_summary     | jsonb                       | NO          | '[]'::jsonb
 severity         | character varying           | NO          | 'info'::character varying
 created_at       | timestamp without time zone | NO          | now()
(9 rows)


-- Table: sessions
 column_name  |          data_type          | is_nullable | column_default 
--------------+-----------------------------+-------------+----------------
 id           | character varying           | NO          | 
 user_id      | integer                     | NO          | 
 created_at   | timestamp without time zone | NO          | now()
 expires_at   | timestamp without time zone | NO          | 
 last_seen_at | timestamp without time zone | NO          | now()
(5 rows)


-- Table: domain_watchlist
 column_name |          data_type          | is_nullable |                column_default                
-------------+-----------------------------+-------------+----------------------------------------------
 id          | integer                     | NO          | nextval('domain_watchlist_id_seq'::regclass)
 user_id     | integer                     | NO          | 
 domain      | character varying           | NO          | 
 cadence     | character varying           | NO          | 'daily'::character varying
 enabled     | boolean                     | NO          | true
 last_run_at | timestamp without time zone | YES         | 
 next_run_at | timestamp without time zone | YES         | 
 created_at  | timestamp without time zone | NO          | now()
(8 rows)


-- Table: notification_endpoints
  column_name  |          data_type          | is_nullable |                   column_default                   
---------------+-----------------------------+-------------+----------------------------------------------------
 id            | integer                     | NO          | nextval('notification_endpoints_id_seq'::regclass)
 user_id       | integer                     | NO          | 
 endpoint_type | character varying           | NO          | 'webhook'::character varying
 url           | text                        | NO          | 
 secret        | character varying           | YES         | 
 enabled       | boolean                     | NO          | true
 created_at    | timestamp without time zone | NO          | now()
(7 rows)


-- Table: ice_protocols
 column_name  |          data_type          | is_nullable |              column_default               
--------------+-----------------------------+-------------+-------------------------------------------
 id           | integer                     | NO          | nextval('ice_protocols_id_seq'::regclass)
 protocol     | character varying           | NO          | 
 display_name | character varying           | NO          | 
 rfc_refs     | ARRAY                       | NO          | '{}'::text[]
 created_at   | timestamp without time zone | NO          | now()
(5 rows)


-- Table: analysis_stats
     column_name     |          data_type          | is_nullable |               column_default               
---------------------+-----------------------------+-------------+--------------------------------------------
 id                  | integer                     | NO          | nextval('analysis_stats_id_seq'::regclass)
 date                | date                        | NO          | 
 total_analyses      | integer                     | YES         | 
 successful_analyses | integer                     | YES         | 
 failed_analyses     | integer                     | YES         | 
 unique_domains      | integer                     | YES         | 
 avg_analysis_time   | double precision            | YES         | 
 created_at          | timestamp without time zone | YES         | 
 updated_at          | timestamp without time zone | YES         | 
(9 rows)


-- Table: data_governance_events
  column_name   |          data_type          | is_nullable |                   column_default                   
----------------+-----------------------------+-------------+----------------------------------------------------
 id             | integer                     | NO          | nextval('data_governance_events_id_seq'::regclass)
 event_type     | character varying           | NO          | 
 description    | text                        | NO          | 
 scope          | text                        | YES         | 
 affected_count | integer                     | YES         | 
 reason         | text                        | NO          | 
 operator       | character varying           | NO          | 'system'::character varying
 metadata       | jsonb                       | YES         | 
 created_at     | timestamp without time zone | NO          | now()
(9 rows)


-- Table: ice_maturity
    column_name     |          data_type          | is_nullable |              column_default              
--------------------+-----------------------------+-------------+------------------------------------------
 id                 | integer                     | NO          | nextval('ice_maturity_id_seq'::regclass)
 protocol           | character varying           | NO          | 
 layer              | character varying           | NO          | 
 maturity           | character varying           | NO          | 'development'::character varying
 total_runs         | integer                     | NO          | 0
 consecutive_passes | integer                     | NO          | 0
 first_pass_at      | timestamp without time zone | YES         | 
 last_regression_at | timestamp without time zone | YES         | 
 last_evaluated_at  | timestamp without time zone | NO          | now()
 updated_at         | timestamp without time zone | NO          | now()
(10 rows)


-- Table: ice_test_runs
 column_name  |          data_type          | is_nullable |              column_default               
--------------+-----------------------------+-------------+-------------------------------------------
 id           | integer                     | NO          | nextval('ice_test_runs_id_seq'::regclass)
 app_version  | character varying           | NO          | 
 git_commit   | character varying           | NO          | ''::character varying
 run_type     | character varying           | NO          | 'ci'::character varying
 total_cases  | integer                     | NO          | 0
 total_passed | integer                     | NO          | 0
 total_failed | integer                     | NO          | 0
 duration_ms  | integer                     | NO          | 0
 created_at   | timestamp without time zone | NO          | now()
(9 rows)


-- Table: user_analyses
 column_name |          data_type          | is_nullable |              column_default               
-------------+-----------------------------+-------------+-------------------------------------------
 id          | integer                     | NO          | nextval('user_analyses_id_seq'::regclass)
 user_id     | integer                     | NO          | 
 analysis_id | integer                     | NO          | 
 created_at  | timestamp without time zone | NO          | now()
(4 rows)


-- Table: users
  column_name  |          data_type          | is_nullable |          column_default           
---------------+-----------------------------+-------------+-----------------------------------
 id            | integer                     | NO          | nextval('users_id_seq'::regclass)
 email         | character varying           | NO          | 
 name          | character varying           | NO          | ''::character varying
 google_sub    | character varying           | NO          | 
 role          | character varying           | NO          | 'user'::character varying
 created_at    | timestamp without time zone | NO          | now()
 last_login_at | timestamp without time zone | NO          | now()
(7 rows)


