-- GENERATED FILE — DO NOT EDIT, AND DO NOT RUN.
--
-- Regenerate with:  ./scripts/regen-schema-doc.sh
--
-- This is `pg_dump --schema-only` of a database built by applying every
-- migration in go-server/db/migrations in order. It exists so the schema can be
-- read in one place. It is NOT a bootstrap path:
--
--   * docker-compose does not mount it into docker-entrypoint-initdb.d
--   * the server does not execute it
--   * the handler tests do not apply it
--
-- All three now go through the same versioned migration chain, which is the
-- only thing that can both create a database AND upgrade an existing one.
-- Editing this file changes nothing except the documentation; schema changes
-- are made by adding a migration.
--
-- The version ledger tables (goose_db_version, schema_migration_checksums) are
-- deliberately absent: they are created by the runner, not by a migration, and
-- they describe bookkeeping rather than the application's data. See
-- go-server/internal/db/migrate.go.
--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: analysis_stats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_stats (
    id integer NOT NULL,
    date date NOT NULL,
    total_analyses integer DEFAULT 0,
    successful_analyses integer DEFAULT 0,
    failed_analyses integer DEFAULT 0,
    unique_domains integer DEFAULT 0,
    avg_analysis_time double precision DEFAULT 0.0,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: analysis_stats_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analysis_stats_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analysis_stats_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analysis_stats_id_seq OWNED BY public.analysis_stats.id;


--
-- Name: analytics_meta; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analytics_meta (
    key text NOT NULL,
    value bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE analytics_meta; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.analytics_meta IS 'Server-side singleton config for analytics. Stores the stable HLL salt (key=hll_salt_v1, 32 bytes, generated once at first server start, never rotated) used to hash (ip, ua) tuples before insertion into HLL sketches. Stable salt enables mergeable HLL union across days for true unique-visitor counting.';


--
-- Name: confidence_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.confidence_scores (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    scan_id uuid,
    domain text NOT NULL,
    protocol text NOT NULL,
    score numeric(5,4) NOT NULL,
    grade text,
    resolver_count smallint,
    resolver_agreement numeric(5,4),
    evidence_factors jsonb DEFAULT '{}'::jsonb NOT NULL,
    calibrated_score numeric(5,4),
    raw_score numeric(5,4),
    source text DEFAULT 'scan'::text NOT NULL,
    scanned_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    analysis_id integer,
    CONSTRAINT confidence_scores_grade_check CHECK ((grade = ANY (ARRAY['A+'::text, 'A'::text, 'A-'::text, 'B+'::text, 'B'::text, 'B-'::text, 'C+'::text, 'C'::text, 'C-'::text, 'D'::text, 'F'::text]))),
    CONSTRAINT confidence_scores_protocol_check CHECK ((protocol = ANY (ARRAY['SPF'::text, 'DKIM'::text, 'DMARC'::text, 'DNSSEC'::text, 'DANE'::text, 'CAA'::text, 'MTA-STS'::text, 'BIMI'::text, 'TLS-RPT'::text, 'MX'::text, 'NS'::text, 'SOA'::text]))),
    CONSTRAINT confidence_scores_score_check CHECK (((score >= (0)::numeric) AND (score <= (1)::numeric))),
    CONSTRAINT confidence_scores_source_check CHECK ((source = ANY (ARRAY['scan'::text, 'manual'::text, 'import'::text, 'recalibration'::text])))
);


--
-- Name: ct_subdomain_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ct_subdomain_cache (
    domain character varying(255) NOT NULL,
    subdomains jsonb DEFAULT '[]'::jsonb NOT NULL,
    unique_count integer DEFAULT 0 NOT NULL,
    source character varying(50) DEFAULT 'crt.sh'::character varying NOT NULL,
    fetched_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL
);


--
-- Name: data_governance_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.data_governance_events (
    id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    description text NOT NULL,
    scope text,
    affected_count integer,
    reason text NOT NULL,
    operator character varying(100) DEFAULT 'system'::character varying NOT NULL,
    metadata jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: data_governance_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.data_governance_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: data_governance_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.data_governance_events_id_seq OWNED BY public.data_governance_events.id;


--
-- Name: domain_analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domain_analyses (
    id integer NOT NULL,
    domain character varying(255) NOT NULL,
    ascii_domain character varying(255) NOT NULL,
    basic_records json,
    authoritative_records json,
    spf_status character varying(20),
    spf_records json,
    dmarc_status character varying(20),
    dmarc_policy character varying(20),
    dmarc_records json,
    dkim_status character varying(20),
    dkim_selectors json,
    registrar_name character varying(255),
    registrar_source character varying(20),
    analysis_success boolean DEFAULT true,
    error_message text,
    analysis_duration double precision,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone,
    country_code character varying(10),
    country_name character varying(100),
    ct_subdomains json,
    full_results json NOT NULL,
    posture_hash character varying(128),
    private boolean DEFAULT false NOT NULL,
    has_user_selectors boolean DEFAULT false NOT NULL,
    scan_flag boolean DEFAULT false NOT NULL,
    scan_source character varying(100),
    scan_ip character varying(45),
    wayback_url text,
    app_version text NOT NULL
);


--
-- Name: domain_analyses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.domain_analyses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: domain_analyses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.domain_analyses_id_seq OWNED BY public.domain_analyses.id;


--
-- Name: domain_index; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domain_index (
    domain character varying(255) NOT NULL,
    first_seen timestamp without time zone DEFAULT now() NOT NULL,
    last_seen timestamp without time zone DEFAULT now() NOT NULL,
    total_scans integer DEFAULT 1 NOT NULL,
    last_score real,
    has_dane boolean DEFAULT false NOT NULL,
    has_dnssec boolean DEFAULT false NOT NULL,
    has_mta_sts boolean DEFAULT false NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL
);


--
-- Name: domain_watchlist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domain_watchlist (
    id integer NOT NULL,
    user_id integer NOT NULL,
    domain character varying(255) NOT NULL,
    cadence character varying(20) DEFAULT 'daily'::character varying NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    last_run_at timestamp without time zone,
    next_run_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: domain_watchlist_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.domain_watchlist_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: domain_watchlist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.domain_watchlist_id_seq OWNED BY public.domain_watchlist.id;


--
-- Name: drift_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drift_events (
    id integer NOT NULL,
    domain character varying(255) NOT NULL,
    analysis_id integer NOT NULL,
    prev_analysis_id integer NOT NULL,
    current_hash character varying(128) NOT NULL,
    previous_hash character varying(128) NOT NULL,
    diff_summary jsonb DEFAULT '[]'::jsonb NOT NULL,
    severity character varying(20) DEFAULT 'info'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: drift_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.drift_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: drift_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.drift_events_id_seq OWNED BY public.drift_events.id;


--
-- Name: drift_notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drift_notifications (
    id integer NOT NULL,
    drift_event_id integer NOT NULL,
    endpoint_id integer NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    response_code integer,
    response_body text,
    delivered_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: drift_notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.drift_notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: drift_notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.drift_notifications_id_seq OWNED BY public.drift_notifications.id;


--
-- Name: ede_amendments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ede_amendments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ede_event_id uuid NOT NULL,
    amendment_date date NOT NULL,
    ground text NOT NULL,
    field_changed text NOT NULL,
    original_value text NOT NULL,
    corrected_to text NOT NULL,
    evidence text,
    rationale text,
    justification text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ede_amendments_ground_check CHECK ((ground = ANY (ARRAY['FACTUAL_ERROR'::text, 'DIGNITY_OF_EXPRESSION'::text])))
);


--
-- Name: ede_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ede_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ede_id text NOT NULL,
    event_date date NOT NULL,
    commit_ref text NOT NULL,
    category text NOT NULL,
    severity text NOT NULL,
    title text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    attribution text NOT NULL,
    protocols_affected jsonb DEFAULT '[]'::jsonb NOT NULL,
    confidence_impact text,
    resolution text,
    bayesian_note text,
    correction_action text,
    prevention_rule text,
    authoritative_source text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ede_events_attribution_check CHECK ((attribution = ANY (ARRAY['Human Error'::text, 'AI Error'::text, 'Both'::text, 'Process Gap'::text]))),
    CONSTRAINT ede_events_category_check CHECK ((category = ANY (ARRAY['scoring_calibration'::text, 'evidence_reinterpretation'::text, 'drift_detection'::text, 'resolver_trust'::text, 'false_positive'::text, 'confidence_decay'::text, 'governance_correction'::text, 'citation_error'::text, 'overclaim'::text, 'standards_misattribution'::text]))),
    CONSTRAINT ede_events_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'significant'::text, 'moderate'::text, 'minor'::text]))),
    CONSTRAINT ede_events_status_check CHECK ((status = ANY (ARRAY['open'::text, 'closed'::text])))
);


--
-- Name: finding_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    finding_id uuid NOT NULL,
    actor text NOT NULL,
    event_type text NOT NULL,
    from_status text,
    to_status text,
    commit_sha text,
    note_md text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT finding_events_event_type_check CHECK ((event_type = ANY (ARRAY['status_change'::text, 'note'::text, 'fix_linked'::text, 'regression'::text, 'verification'::text])))
);


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    public_id text NOT NULL,
    kind text NOT NULL,
    domain text NOT NULL,
    title text NOT NULL,
    symptom_md text NOT NULL,
    hypothesis_md text,
    root_cause_md text,
    severity smallint NOT NULL,
    priority smallint NOT NULL,
    status text DEFAULT 'DETAINED'::text NOT NULL,
    canonical_rule_id text NOT NULL,
    fingerprint_version smallint DEFAULT 1 NOT NULL,
    fingerprint_sha256 character(64) NOT NULL,
    evidence_grade text NOT NULL,
    confidence numeric(3,2) NOT NULL,
    blast_radius text NOT NULL,
    visibility text NOT NULL,
    standard_refs jsonb DEFAULT '[]'::jsonb NOT NULL,
    duplicate_of uuid,
    regression_of uuid,
    source_team text DEFAULT ''::text NOT NULL,
    owner text,
    introduced_commit text,
    fixed_commit text,
    fixed_release text,
    legacy_bsi_id text,
    legacy_threat_level text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT findings_blast_radius_check CHECK ((blast_radius = ANY (ARRAY['component'::text, 'page'::text, 'flow'::text, 'sitewide'::text]))),
    CONSTRAINT findings_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric))),
    CONSTRAINT findings_domain_check CHECK ((domain = ANY (ARRAY['security'::text, 'accessibility'::text, 'ux'::text, 'performance'::text, 'seo'::text, 'content'::text, 'design_system'::text, 'architecture'::text]))),
    CONSTRAINT findings_evidence_grade_check CHECK ((evidence_grade = ANY (ARRAY['measured'::text, 'reproduced'::text, 'static_analysis'::text, 'inferred'::text]))),
    CONSTRAINT findings_kind_check CHECK ((kind = ANY (ARRAY['defect'::text, 'weakness'::text, 'incident'::text, 'compliance_gap'::text, 'claim_integrity'::text, 'design_debt'::text]))),
    CONSTRAINT findings_priority_check CHECK (((priority >= 0) AND (priority <= 3))),
    CONSTRAINT findings_severity_check CHECK (((severity >= 0) AND (severity <= 4))),
    CONSTRAINT findings_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'VERIFIED'::text, 'UNDER_ANALYSIS'::text, 'CONTAINED'::text, 'RESOLVED'::text, 'REGRESSED'::text, 'REFERRED'::text, 'DISMISSED'::text]))),
    CONSTRAINT findings_visibility_check CHECK ((visibility = ANY (ARRAY['internal'::text, 'edge_case'::text, 'common'::text, 'critical_path'::text, 'conference_demo'::text])))
);


--
-- Name: flux_observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.flux_observations (
    id integer NOT NULL,
    analysis_id integer NOT NULL,
    domain character varying(255) NOT NULL,
    observed_at timestamp without time zone DEFAULT now() NOT NULL,
    asn_set text[] DEFAULT '{}'::text[] NOT NULL,
    ttl integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: flux_observations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.flux_observations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: flux_observations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.flux_observations_id_seq OWNED BY public.flux_observations.id;


--
-- Name: ice_maturity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ice_maturity (
    id integer NOT NULL,
    protocol character varying(20) NOT NULL,
    layer character varying(20) NOT NULL,
    maturity character varying(20) DEFAULT 'development'::character varying NOT NULL,
    total_runs integer DEFAULT 0 NOT NULL,
    consecutive_passes integer DEFAULT 0 NOT NULL,
    first_pass_at timestamp without time zone,
    last_regression_at timestamp without time zone,
    last_evaluated_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ice_maturity_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ice_maturity_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ice_maturity_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ice_maturity_id_seq OWNED BY public.ice_maturity.id;


--
-- Name: ice_protocols; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ice_protocols (
    id integer NOT NULL,
    protocol character varying(20) NOT NULL,
    display_name character varying(50) NOT NULL,
    rfc_refs text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ice_protocols_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ice_protocols_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ice_protocols_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ice_protocols_id_seq OWNED BY public.ice_protocols.id;


--
-- Name: ice_regressions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ice_regressions (
    id integer NOT NULL,
    protocol character varying(20) NOT NULL,
    layer character varying(20) NOT NULL,
    run_id integer NOT NULL,
    previous_maturity character varying(20) NOT NULL,
    new_maturity character varying(20) NOT NULL,
    failed_cases text[] DEFAULT '{}'::text[] NOT NULL,
    notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ice_regressions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ice_regressions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ice_regressions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ice_regressions_id_seq OWNED BY public.ice_regressions.id;


--
-- Name: ice_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ice_results (
    id integer NOT NULL,
    run_id integer NOT NULL,
    protocol character varying(20) NOT NULL,
    layer character varying(20) NOT NULL,
    case_id character varying(100) NOT NULL,
    case_name character varying(255) DEFAULT ''::character varying NOT NULL,
    passed boolean NOT NULL,
    expected text,
    actual text,
    rfc_section character varying(50),
    notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ice_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ice_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ice_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ice_results_id_seq OWNED BY public.ice_results.id;


--
-- Name: ice_test_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ice_test_runs (
    id integer NOT NULL,
    app_version text NOT NULL,
    git_commit character varying(40) DEFAULT ''::character varying NOT NULL,
    run_type character varying(20) DEFAULT 'ci'::character varying NOT NULL,
    total_cases integer DEFAULT 0 NOT NULL,
    total_passed integer DEFAULT 0 NOT NULL,
    total_failed integer DEFAULT 0 NOT NULL,
    duration_ms integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ice_test_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ice_test_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ice_test_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ice_test_runs_id_seq OWNED BY public.ice_test_runs.id;


--
-- Name: icuae_dimension_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.icuae_dimension_scores (
    id integer NOT NULL,
    scan_id integer NOT NULL,
    dimension character varying(50) NOT NULL,
    score real DEFAULT 0 NOT NULL,
    grade character varying(20) NOT NULL,
    record_types_evaluated integer DEFAULT 0 NOT NULL,
    record_types_list text[] DEFAULT '{}'::text[] NOT NULL
);


--
-- Name: icuae_dimension_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.icuae_dimension_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: icuae_dimension_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.icuae_dimension_scores_id_seq OWNED BY public.icuae_dimension_scores.id;


--
-- Name: icuae_scan_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.icuae_scan_scores (
    id integer NOT NULL,
    domain character varying(255) NOT NULL,
    overall_score real DEFAULT 0 NOT NULL,
    overall_grade character varying(20) NOT NULL,
    resolver_count integer DEFAULT 0 NOT NULL,
    record_count integer DEFAULT 0 NOT NULL,
    app_version text DEFAULT ''::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: icuae_scan_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.icuae_scan_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: icuae_scan_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.icuae_scan_scores_id_seq OWNED BY public.icuae_scan_scores.id;


--
-- Name: notification_endpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_endpoints (
    id integer NOT NULL,
    user_id integer NOT NULL,
    endpoint_type character varying(20) DEFAULT 'webhook'::character varying NOT NULL,
    url text NOT NULL,
    secret character varying(128),
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: notification_endpoints_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.notification_endpoints_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notification_endpoints_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.notification_endpoints_id_seq OWNED BY public.notification_endpoints.id;


--
-- Name: observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.observations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    finding_id uuid NOT NULL,
    source_team text NOT NULL,
    build_id text,
    route text,
    component text,
    browser text,
    viewport text,
    repro_steps_md text,
    evidence_sha256 character(64) NOT NULL,
    raw_evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: priority_domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.priority_domains (
    domain character varying(255) NOT NULL,
    reason text NOT NULL,
    added_at timestamp without time zone DEFAULT now() NOT NULL,
    enabled boolean DEFAULT true NOT NULL
);


--
-- Name: scan_api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_api_keys (
    id integer NOT NULL,
    label text NOT NULL,
    key_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    use_count integer DEFAULT 0 NOT NULL,
    revoked_at timestamp with time zone
);


--
-- Name: scan_api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scan_api_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scan_api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scan_api_keys_id_seq OWNED BY public.scan_api_keys.id;


--
-- Name: scan_phase_telemetry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_phase_telemetry (
    id integer NOT NULL,
    analysis_id integer NOT NULL,
    phase_group text NOT NULL,
    phase_task text NOT NULL,
    started_at_ms integer NOT NULL,
    duration_ms integer NOT NULL,
    record_count integer DEFAULT 0,
    error text,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: scan_phase_telemetry_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scan_phase_telemetry_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scan_phase_telemetry_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scan_phase_telemetry_id_seq OWNED BY public.scan_phase_telemetry.id;


--
-- Name: scan_telemetry_hash; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_telemetry_hash (
    analysis_id integer NOT NULL,
    total_duration_ms integer NOT NULL,
    phase_count integer NOT NULL,
    sha3_512 text NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: securitytrails_budget; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.securitytrails_budget (
    month_key character varying(7) NOT NULL,
    calls_used integer DEFAULT 0 NOT NULL,
    domains_enriched jsonb DEFAULT '[]'::jsonb NOT NULL,
    last_called_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    last_seen_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: site_analytics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.site_analytics (
    id integer NOT NULL,
    date date NOT NULL,
    pageviews integer DEFAULT 0 NOT NULL,
    unique_visitors integer DEFAULT 0 NOT NULL,
    analyses_run integer DEFAULT 0 NOT NULL,
    unique_domains_analyzed integer DEFAULT 0 NOT NULL,
    referrer_sources jsonb DEFAULT '{}'::jsonb NOT NULL,
    top_pages jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    hll_visitors bytea
);


--
-- Name: COLUMN site_analytics.hll_visitors; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.site_analytics.hll_visitors IS 'HyperLogLog++ sketch (precision=14, m=16384) of stable-salted visitor hashes. Mergeable across days; expected relative standard error ~0.81%. Stores only register max values, no individual identifiers. Implementation: github.com/axiomhq/hyperloglog v0.2.6.';


--
-- Name: site_analytics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.site_analytics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: site_analytics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.site_analytics_id_seq OWNED BY public.site_analytics.id;


--
-- Name: system_log_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_log_entries (
    id integer NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    level character varying(10) DEFAULT 'INFO'::character varying NOT NULL,
    message text DEFAULT ''::text NOT NULL,
    event character varying(50) DEFAULT ''::character varying NOT NULL,
    category character varying(30) DEFAULT ''::character varying NOT NULL,
    domain character varying(255) DEFAULT ''::character varying NOT NULL,
    trace_id character varying(64) DEFAULT ''::character varying NOT NULL,
    attrs jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: system_log_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.system_log_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: system_log_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.system_log_entries_id_seq OWNED BY public.system_log_entries.id;


--
-- Name: user_analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_analyses (
    id integer NOT NULL,
    user_id integer NOT NULL,
    analysis_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: user_analyses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_analyses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_analyses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_analyses_id_seq OWNED BY public.user_analyses.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255) DEFAULT ''::character varying NOT NULL,
    google_sub character varying(255) NOT NULL,
    role character varying(20) DEFAULT 'user'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    last_login_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: zone_imports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.zone_imports (
    id integer NOT NULL,
    user_id integer NOT NULL,
    domain character varying(255) NOT NULL,
    sha256_hash character varying(64) NOT NULL,
    original_filename character varying(255) NOT NULL,
    file_size integer NOT NULL,
    record_count integer DEFAULT 0 NOT NULL,
    retained boolean DEFAULT false NOT NULL,
    zone_data text,
    drift_summary jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: zone_imports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.zone_imports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: zone_imports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.zone_imports_id_seq OWNED BY public.zone_imports.id;


--
-- Name: analysis_stats id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_stats ALTER COLUMN id SET DEFAULT nextval('public.analysis_stats_id_seq'::regclass);


--
-- Name: data_governance_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_governance_events ALTER COLUMN id SET DEFAULT nextval('public.data_governance_events_id_seq'::regclass);


--
-- Name: domain_analyses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_analyses ALTER COLUMN id SET DEFAULT nextval('public.domain_analyses_id_seq'::regclass);


--
-- Name: domain_watchlist id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_watchlist ALTER COLUMN id SET DEFAULT nextval('public.domain_watchlist_id_seq'::regclass);


--
-- Name: drift_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_events ALTER COLUMN id SET DEFAULT nextval('public.drift_events_id_seq'::regclass);


--
-- Name: drift_notifications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications ALTER COLUMN id SET DEFAULT nextval('public.drift_notifications_id_seq'::regclass);


--
-- Name: flux_observations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.flux_observations ALTER COLUMN id SET DEFAULT nextval('public.flux_observations_id_seq'::regclass);


--
-- Name: ice_maturity id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_maturity ALTER COLUMN id SET DEFAULT nextval('public.ice_maturity_id_seq'::regclass);


--
-- Name: ice_protocols id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_protocols ALTER COLUMN id SET DEFAULT nextval('public.ice_protocols_id_seq'::regclass);


--
-- Name: ice_regressions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_regressions ALTER COLUMN id SET DEFAULT nextval('public.ice_regressions_id_seq'::regclass);


--
-- Name: ice_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_results ALTER COLUMN id SET DEFAULT nextval('public.ice_results_id_seq'::regclass);


--
-- Name: ice_test_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_test_runs ALTER COLUMN id SET DEFAULT nextval('public.ice_test_runs_id_seq'::regclass);


--
-- Name: icuae_dimension_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.icuae_dimension_scores ALTER COLUMN id SET DEFAULT nextval('public.icuae_dimension_scores_id_seq'::regclass);


--
-- Name: icuae_scan_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.icuae_scan_scores ALTER COLUMN id SET DEFAULT nextval('public.icuae_scan_scores_id_seq'::regclass);


--
-- Name: notification_endpoints id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_endpoints ALTER COLUMN id SET DEFAULT nextval('public.notification_endpoints_id_seq'::regclass);


--
-- Name: scan_api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_api_keys ALTER COLUMN id SET DEFAULT nextval('public.scan_api_keys_id_seq'::regclass);


--
-- Name: scan_phase_telemetry id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_phase_telemetry ALTER COLUMN id SET DEFAULT nextval('public.scan_phase_telemetry_id_seq'::regclass);


--
-- Name: site_analytics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.site_analytics ALTER COLUMN id SET DEFAULT nextval('public.site_analytics_id_seq'::regclass);


--
-- Name: system_log_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_log_entries ALTER COLUMN id SET DEFAULT nextval('public.system_log_entries_id_seq'::regclass);


--
-- Name: user_analyses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_analyses ALTER COLUMN id SET DEFAULT nextval('public.user_analyses_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: zone_imports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zone_imports ALTER COLUMN id SET DEFAULT nextval('public.zone_imports_id_seq'::regclass);


--
-- Name: analysis_stats analysis_stats_date_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_stats
    ADD CONSTRAINT analysis_stats_date_key UNIQUE (date);


--
-- Name: analysis_stats analysis_stats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_stats
    ADD CONSTRAINT analysis_stats_pkey PRIMARY KEY (id);


--
-- Name: analytics_meta analytics_meta_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analytics_meta
    ADD CONSTRAINT analytics_meta_pkey PRIMARY KEY (key);


--
-- Name: confidence_scores confidence_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.confidence_scores
    ADD CONSTRAINT confidence_scores_pkey PRIMARY KEY (id);


--
-- Name: ct_subdomain_cache ct_subdomain_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ct_subdomain_cache
    ADD CONSTRAINT ct_subdomain_cache_pkey PRIMARY KEY (domain);


--
-- Name: data_governance_events data_governance_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_governance_events
    ADD CONSTRAINT data_governance_events_pkey PRIMARY KEY (id);


--
-- Name: domain_analyses domain_analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_analyses
    ADD CONSTRAINT domain_analyses_pkey PRIMARY KEY (id);


--
-- Name: domain_index domain_index_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_index
    ADD CONSTRAINT domain_index_pkey PRIMARY KEY (domain);


--
-- Name: domain_watchlist domain_watchlist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_watchlist
    ADD CONSTRAINT domain_watchlist_pkey PRIMARY KEY (id);


--
-- Name: domain_watchlist domain_watchlist_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_watchlist
    ADD CONSTRAINT domain_watchlist_unique UNIQUE (user_id, domain);


--
-- Name: drift_events drift_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_events
    ADD CONSTRAINT drift_events_pkey PRIMARY KEY (id);


--
-- Name: drift_notifications drift_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_pkey PRIMARY KEY (id);


--
-- Name: ede_amendments ede_amendments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ede_amendments
    ADD CONSTRAINT ede_amendments_pkey PRIMARY KEY (id);


--
-- Name: ede_events ede_events_ede_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ede_events
    ADD CONSTRAINT ede_events_ede_id_key UNIQUE (ede_id);


--
-- Name: ede_events ede_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ede_events
    ADD CONSTRAINT ede_events_pkey PRIMARY KEY (id);


--
-- Name: finding_events finding_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_events
    ADD CONSTRAINT finding_events_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: findings findings_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_public_id_key UNIQUE (public_id);


--
-- Name: flux_observations flux_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.flux_observations
    ADD CONSTRAINT flux_observations_pkey PRIMARY KEY (id);


--
-- Name: ice_maturity ice_maturity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_maturity
    ADD CONSTRAINT ice_maturity_pkey PRIMARY KEY (id);


--
-- Name: ice_maturity ice_maturity_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_maturity
    ADD CONSTRAINT ice_maturity_unique UNIQUE (protocol, layer);


--
-- Name: ice_protocols ice_protocols_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_protocols
    ADD CONSTRAINT ice_protocols_pkey PRIMARY KEY (id);


--
-- Name: ice_protocols ice_protocols_protocol_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_protocols
    ADD CONSTRAINT ice_protocols_protocol_key UNIQUE (protocol);


--
-- Name: ice_regressions ice_regressions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_regressions
    ADD CONSTRAINT ice_regressions_pkey PRIMARY KEY (id);


--
-- Name: ice_results ice_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_results
    ADD CONSTRAINT ice_results_pkey PRIMARY KEY (id);


--
-- Name: ice_test_runs ice_test_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_test_runs
    ADD CONSTRAINT ice_test_runs_pkey PRIMARY KEY (id);


--
-- Name: icuae_dimension_scores icuae_dimension_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.icuae_dimension_scores
    ADD CONSTRAINT icuae_dimension_scores_pkey PRIMARY KEY (id);


--
-- Name: icuae_scan_scores icuae_scan_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.icuae_scan_scores
    ADD CONSTRAINT icuae_scan_scores_pkey PRIMARY KEY (id);


--
-- Name: notification_endpoints notification_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_endpoints
    ADD CONSTRAINT notification_endpoints_pkey PRIMARY KEY (id);


--
-- Name: observations observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.observations
    ADD CONSTRAINT observations_pkey PRIMARY KEY (id);


--
-- Name: priority_domains priority_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.priority_domains
    ADD CONSTRAINT priority_domains_pkey PRIMARY KEY (domain);


--
-- Name: scan_api_keys scan_api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_api_keys
    ADD CONSTRAINT scan_api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: scan_api_keys scan_api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_api_keys
    ADD CONSTRAINT scan_api_keys_pkey PRIMARY KEY (id);


--
-- Name: scan_phase_telemetry scan_phase_telemetry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_phase_telemetry
    ADD CONSTRAINT scan_phase_telemetry_pkey PRIMARY KEY (id);


--
-- Name: scan_telemetry_hash scan_telemetry_hash_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_telemetry_hash
    ADD CONSTRAINT scan_telemetry_hash_pkey PRIMARY KEY (analysis_id);


--
-- Name: securitytrails_budget securitytrails_budget_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.securitytrails_budget
    ADD CONSTRAINT securitytrails_budget_pkey PRIMARY KEY (month_key);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: site_analytics site_analytics_date_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.site_analytics
    ADD CONSTRAINT site_analytics_date_key UNIQUE (date);


--
-- Name: site_analytics site_analytics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.site_analytics
    ADD CONSTRAINT site_analytics_pkey PRIMARY KEY (id);


--
-- Name: system_log_entries system_log_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_log_entries
    ADD CONSTRAINT system_log_entries_pkey PRIMARY KEY (id);


--
-- Name: user_analyses user_analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_analyses
    ADD CONSTRAINT user_analyses_pkey PRIMARY KEY (id);


--
-- Name: user_analyses user_analyses_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_analyses
    ADD CONSTRAINT user_analyses_unique UNIQUE (user_id, analysis_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_google_sub_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_google_sub_key UNIQUE (google_sub);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: zone_imports zone_imports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zone_imports
    ADD CONSTRAINT zone_imports_pkey PRIMARY KEY (id);


--
-- Name: findings_canonical_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX findings_canonical_uq ON public.findings USING btree (canonical_rule_id, fingerprint_version, fingerprint_sha256) WHERE (duplicate_of IS NULL);


--
-- Name: idx_confidence_scores_analysis_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_confidence_scores_analysis_id ON public.confidence_scores USING btree (analysis_id);


--
-- Name: idx_confidence_scores_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_confidence_scores_domain ON public.confidence_scores USING btree (domain);


--
-- Name: idx_confidence_scores_domain_protocol; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_confidence_scores_domain_protocol ON public.confidence_scores USING btree (domain, protocol);


--
-- Name: idx_confidence_scores_protocol; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_confidence_scores_protocol ON public.confidence_scores USING btree (protocol);


--
-- Name: idx_confidence_scores_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_confidence_scores_scan_id ON public.confidence_scores USING btree (scan_id);


--
-- Name: idx_confidence_scores_scanned_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_confidence_scores_scanned_at ON public.confidence_scores USING btree (scanned_at);


--
-- Name: idx_ede_amendments_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ede_amendments_event ON public.ede_amendments USING btree (ede_event_id);


--
-- Name: idx_ede_events_attribution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ede_events_attribution ON public.ede_events USING btree (attribution);


--
-- Name: idx_ede_events_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ede_events_category ON public.ede_events USING btree (category);


--
-- Name: idx_ede_events_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ede_events_date ON public.ede_events USING btree (event_date);


--
-- Name: idx_ede_events_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ede_events_severity ON public.ede_events USING btree (severity);


--
-- Name: idx_ede_events_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ede_events_status ON public.ede_events USING btree (status);


--
-- Name: idx_finding_events_finding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_events_finding ON public.finding_events USING btree (finding_id);


--
-- Name: idx_finding_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_events_type ON public.finding_events USING btree (event_type);


--
-- Name: idx_findings_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_domain ON public.findings USING btree (domain);


--
-- Name: idx_findings_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_kind ON public.findings USING btree (kind);


--
-- Name: idx_findings_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_public_id ON public.findings USING btree (public_id);


--
-- Name: idx_findings_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_severity ON public.findings USING btree (severity);


--
-- Name: idx_findings_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_status ON public.findings USING btree (status);


--
-- Name: idx_observations_finding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_observations_finding ON public.observations USING btree (finding_id);


--
-- Name: idx_sle_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sle_category ON public.system_log_entries USING btree (category) WHERE ((category)::text <> ''::text);


--
-- Name: idx_sle_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sle_domain ON public.system_log_entries USING btree (domain) WHERE ((domain)::text <> ''::text);


--
-- Name: idx_sle_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sle_event ON public.system_log_entries USING btree (event) WHERE ((event)::text <> ''::text);


--
-- Name: idx_sle_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sle_level ON public.system_log_entries USING btree (level);


--
-- Name: idx_sle_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sle_timestamp ON public.system_log_entries USING btree ("timestamp" DESC);


--
-- Name: idx_sle_trace_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sle_trace_id ON public.system_log_entries USING btree (trace_id) WHERE ((trace_id)::text <> ''::text);


--
-- Name: idx_spt_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spt_analysis ON public.scan_phase_telemetry USING btree (analysis_id);


--
-- Name: idx_spt_phase; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spt_phase ON public.scan_phase_telemetry USING btree (phase_group);


--
-- Name: ix_analysis_stats_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_stats_date ON public.analysis_stats USING btree (date);


--
-- Name: ix_ct_cache_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ct_cache_expires ON public.ct_subdomain_cache USING btree (expires_at);


--
-- Name: ix_ct_cache_fetched; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ct_cache_fetched ON public.ct_subdomain_cache USING btree (fetched_at DESC);


--
-- Name: ix_da_dnssec_chain_of_trust; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_da_dnssec_chain_of_trust ON public.domain_analyses USING btree ((((full_results -> 'dnssec_analysis'::text) ->> 'chain_of_trust'::text)));


--
-- Name: ix_da_dnssec_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_da_dnssec_state ON public.domain_analyses USING btree ((((full_results -> 'dnssec_analysis'::text) ->> 'dnssec_state'::text)));


--
-- Name: ix_da_request_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_da_request_source ON public.domain_analyses USING btree (((full_results ->> '_request_source'::text)));


--
-- Name: ix_domain_analyses_ascii_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_analyses_ascii_domain ON public.domain_analyses USING btree (ascii_domain);


--
-- Name: ix_domain_analyses_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_analyses_created_at ON public.domain_analyses USING btree (created_at);


--
-- Name: ix_domain_analyses_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_analyses_domain ON public.domain_analyses USING btree (domain);


--
-- Name: ix_domain_analyses_success_results; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_analyses_success_results ON public.domain_analyses USING btree (analysis_success, created_at);


--
-- Name: ix_domain_index_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_index_last_seen ON public.domain_index USING btree (last_seen DESC);


--
-- Name: ix_domain_index_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_index_tags ON public.domain_index USING gin (tags);


--
-- Name: ix_domain_index_total_scans; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_index_total_scans ON public.domain_index USING btree (total_scans DESC);


--
-- Name: ix_domain_watchlist_next_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_watchlist_next_run ON public.domain_watchlist USING btree (next_run_at) WHERE (enabled = true);


--
-- Name: ix_domain_watchlist_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_domain_watchlist_user ON public.domain_watchlist USING btree (user_id);


--
-- Name: ix_drift_events_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_events_analysis ON public.drift_events USING btree (analysis_id);


--
-- Name: ix_drift_events_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_events_domain ON public.drift_events USING btree (domain, created_at DESC);


--
-- Name: ix_drift_notifications_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_event ON public.drift_notifications USING btree (drift_event_id);


--
-- Name: ix_drift_notifications_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_status ON public.drift_notifications USING btree (status) WHERE ((status)::text = 'pending'::text);


--
-- Name: ix_flux_obs_asn_set; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_flux_obs_asn_set ON public.flux_observations USING gin (asn_set);


--
-- Name: ix_flux_obs_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_flux_obs_domain ON public.flux_observations USING btree (domain);


--
-- Name: ix_flux_obs_observed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_flux_obs_observed_at ON public.flux_observations USING btree (observed_at);


--
-- Name: ix_ice_regressions_protocol; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ice_regressions_protocol ON public.ice_regressions USING btree (protocol, layer, created_at);


--
-- Name: ix_ice_results_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ice_results_case ON public.ice_results USING btree (case_id);


--
-- Name: ix_ice_results_protocol; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ice_results_protocol ON public.ice_results USING btree (protocol, layer);


--
-- Name: ix_ice_results_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ice_results_run ON public.ice_results USING btree (run_id);


--
-- Name: ix_ice_test_runs_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ice_test_runs_created ON public.ice_test_runs USING btree (created_at);


--
-- Name: ix_ice_test_runs_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ice_test_runs_version ON public.ice_test_runs USING btree (app_version);


--
-- Name: ix_notification_endpoints_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_notification_endpoints_user ON public.notification_endpoints USING btree (user_id);


--
-- Name: ix_scan_api_keys_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_api_keys_hash ON public.scan_api_keys USING btree (key_hash) WHERE (revoked_at IS NULL);


--
-- Name: ix_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sessions_expires_at ON public.sessions USING btree (expires_at);


--
-- Name: ix_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sessions_user_id ON public.sessions USING btree (user_id);


--
-- Name: ix_site_analytics_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_site_analytics_date ON public.site_analytics USING btree (date);


--
-- Name: ix_user_analyses_analysis_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_analyses_analysis_id ON public.user_analyses USING btree (analysis_id);


--
-- Name: ix_user_analyses_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_analyses_user_id ON public.user_analyses USING btree (user_id, created_at DESC);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: ix_users_google_sub; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_users_google_sub ON public.users USING btree (google_sub);


--
-- Name: ix_zone_imports_user_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_zone_imports_user_domain ON public.zone_imports USING btree (user_id, domain, created_at DESC);


--
-- Name: uq_confidence_scores_analysis_protocol; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_confidence_scores_analysis_protocol ON public.confidence_scores USING btree (analysis_id, protocol) WHERE (analysis_id IS NOT NULL);


--
-- Name: confidence_scores confidence_scores_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.confidence_scores
    ADD CONSTRAINT confidence_scores_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: domain_watchlist domain_watchlist_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_watchlist
    ADD CONSTRAINT domain_watchlist_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: drift_events drift_events_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_events
    ADD CONSTRAINT drift_events_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: drift_events drift_events_prev_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_events
    ADD CONSTRAINT drift_events_prev_analysis_id_fkey FOREIGN KEY (prev_analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: drift_notifications drift_notifications_drift_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_drift_event_id_fkey FOREIGN KEY (drift_event_id) REFERENCES public.drift_events(id) ON DELETE CASCADE;


--
-- Name: drift_notifications drift_notifications_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES public.notification_endpoints(id) ON DELETE CASCADE;


--
-- Name: ede_amendments ede_amendments_ede_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ede_amendments
    ADD CONSTRAINT ede_amendments_ede_event_id_fkey FOREIGN KEY (ede_event_id) REFERENCES public.ede_events(id) ON DELETE CASCADE;


--
-- Name: finding_events finding_events_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_events
    ADD CONSTRAINT finding_events_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: findings findings_duplicate_of_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_duplicate_of_fkey FOREIGN KEY (duplicate_of) REFERENCES public.findings(id);


--
-- Name: findings findings_regression_of_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_regression_of_fkey FOREIGN KEY (regression_of) REFERENCES public.findings(id);


--
-- Name: flux_observations flux_observations_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.flux_observations
    ADD CONSTRAINT flux_observations_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: ice_regressions ice_regressions_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_regressions
    ADD CONSTRAINT ice_regressions_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.ice_test_runs(id) ON DELETE CASCADE;


--
-- Name: ice_results ice_results_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ice_results
    ADD CONSTRAINT ice_results_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.ice_test_runs(id) ON DELETE CASCADE;


--
-- Name: icuae_dimension_scores icuae_dimension_scores_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.icuae_dimension_scores
    ADD CONSTRAINT icuae_dimension_scores_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.icuae_scan_scores(id) ON DELETE CASCADE;


--
-- Name: notification_endpoints notification_endpoints_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_endpoints
    ADD CONSTRAINT notification_endpoints_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: observations observations_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.observations
    ADD CONSTRAINT observations_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: scan_phase_telemetry scan_phase_telemetry_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_phase_telemetry
    ADD CONSTRAINT scan_phase_telemetry_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: scan_telemetry_hash scan_telemetry_hash_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_telemetry_hash
    ADD CONSTRAINT scan_telemetry_hash_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_analyses user_analyses_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_analyses
    ADD CONSTRAINT user_analyses_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.domain_analyses(id) ON DELETE CASCADE;


--
-- Name: user_analyses user_analyses_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_analyses
    ADD CONSTRAINT user_analyses_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: zone_imports zone_imports_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zone_imports
    ADD CONSTRAINT zone_imports_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


