"""Add writer-bound, least-privilege production runtime persistence.

Revision ID: 0008_runtime_persistence
Revises: 0007_preview_persistence
Create Date: 2026-07-31
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0008_runtime_persistence"
down_revision: Union[str, Sequence[str], None] = "0007_preview_persistence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    _create_postgresql_runtime_functions()
    _apply_postgresql_runtime_grants()


def _create_postgresql_runtime_functions() -> None:
    op.execute(
        r"""
        CREATE FUNCTION pilot_guard_storage_reconfiguration()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            current_storage jsonb;
            proposed_storage jsonb;
        BEGIN
            IF NOT pg_try_advisory_xact_lock(
                hashtextextended(
                    'kuzet-retention:' || NEW.site_id,
                    12
                )
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55P03',
                    MESSAGE =
                      'configuration activation is fenced by retention';
            END IF;
            SELECT config.canonical_config->'storage'
              INTO current_storage
              FROM public.active_pilot_configurations AS active
              JOIN public.site_config_revisions AS config
                ON config.site_id = active.site_id
               AND config.config_revision_id =
                   active.config_revision_id
             WHERE active.site_id = NEW.site_id
             FOR SHARE OF active, config;
            IF NOT FOUND THEN
                RETURN NEW;
            END IF;
            SELECT config.canonical_config->'storage'
              INTO proposed_storage
              FROM public.site_config_revisions AS config
             WHERE config.site_id = NEW.site_id
               AND config.config_revision_id =
                   NEW.config_revision_id
             FOR SHARE;
            IF proposed_storage IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'proposed reviewed storage configuration is absent';
            END IF;
            IF proposed_storage IS DISTINCT FROM current_storage THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'reviewed storage is immutable after first activation';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER
          trg_configuration_activation_storage_guard
        BEFORE INSERT ON configuration_activations
        FOR EACH ROW
        EXECUTE FUNCTION
          pilot_guard_storage_reconfiguration()
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_runtime_receipt_is_current(
            p_receipt_canonical_json text,
            p_receipt_sha256 text
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            expected_rule_digests jsonb;
        BEGIN
            IF p_receipt_canonical_json IS NULL
               OR octet_length(p_receipt_canonical_json) > 131072
               OR p_receipt_sha256 !~ '^[0-9a-f]{64}$'
               OR encode(
                    sha256(
                      convert_to(p_receipt_canonical_json, 'UTF8')
                    ),
                    'hex'
                  ) <> p_receipt_sha256
            THEN
                RETURN false;
            END IF;
            receipt := p_receipt_canonical_json::jsonb;
            IF (
                 SELECT count(*)
                   FROM jsonb_object_keys(receipt)
               ) <> 11
               OR NOT (
                    receipt ?& ARRAY[
                        'schema_version',
                        'site_id',
                        'runtime_session_id',
                        'runtime_writer_generation',
                        'configuration_activation_generation',
                        'config_revision_id',
                        'site_config_sha256',
                        'ruleset_revision_id',
                        'ruleset_sha256',
                        'rule_revision_digests',
                        'issued_at'
                    ]
               )
               OR receipt->>'schema_version'
                    <> 'runtime-writer-receipt.v1'
               OR receipt->>'site_id'
                    !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
               OR receipt->>'runtime_session_id'
                    !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
               OR jsonb_typeof(
                    receipt->'runtime_writer_generation'
                  ) <> 'number'
               OR receipt->>'runtime_writer_generation'
                    !~ '^[1-9][0-9]*$'
               OR jsonb_typeof(
                    receipt->'configuration_activation_generation'
                  ) <> 'number'
               OR receipt->>'configuration_activation_generation'
                    !~ '^[1-9][0-9]*$'
               OR receipt->>'config_revision_id'
                    !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
               OR receipt->>'ruleset_revision_id'
                    !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
               OR receipt->>'site_config_sha256'
                    !~ '^[0-9a-f]{64}$'
               OR receipt->>'ruleset_sha256'
                    !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(
                    receipt->'rule_revision_digests'
                  ) <> 'object'
               OR (
                    SELECT count(*)
                      FROM jsonb_object_keys(
                             receipt->'rule_revision_digests'
                           )
                  ) NOT BETWEEN 1 AND 512
               OR EXISTS (
                    SELECT 1
                      FROM jsonb_each_text(
                            receipt->'rule_revision_digests'
                      ) AS digest(rule_id, sha256)
                     WHERE digest.rule_id
                            !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
                        OR digest.sha256 !~ '^[0-9a-f]{64}$'
               )
            THEN
                RETURN false;
            END IF;

            SELECT jsonb_object_agg(
                       rule.rule_id,
                       rule.rule_revision_sha256
                       ORDER BY rule.rule_id
                   )
              INTO expected_rule_digests
              FROM public.camera_rule_revisions AS rule
             WHERE rule.ruleset_revision_id =
                   receipt->>'ruleset_revision_id';
            IF expected_rule_digests IS NULL
               OR expected_rule_digests
                    <> receipt->'rule_revision_digests'
            THEN
                RETURN false;
            END IF;

            PERFORM 1
              FROM public.active_pilot_configurations AS active
              JOIN public.site_config_revisions AS config
                ON config.site_id = active.site_id
               AND config.config_revision_id =
                   active.config_revision_id
              JOIN public.camera_ruleset_revisions AS ruleset
                ON ruleset.site_id = active.site_id
               AND ruleset.config_revision_id =
                   active.config_revision_id
               AND ruleset.ruleset_revision_id =
                   active.ruleset_revision_id
              JOIN public.runtime_writer_authorities AS writer
                ON writer.site_id = active.site_id
              JOIN public.runtime_writer_sessions AS history
                ON history.site_id = active.site_id
               AND history.runtime_session_id =
                   writer.runtime_session_id
               AND history.writer_generation =
                   writer.writer_generation
               AND history.configuration_activation_generation =
                   writer.configuration_activation_generation
             WHERE active.site_id = receipt->>'site_id'
               AND active.activation_generation =
                   (
                     receipt
                     ->>'configuration_activation_generation'
                   )::bigint
               AND active.config_revision_id =
                   receipt->>'config_revision_id'
               AND active.ruleset_revision_id =
                   receipt->>'ruleset_revision_id'
               AND config.config_sha256 =
                   receipt->>'site_config_sha256'
               AND ruleset.site_config_sha256 =
                   receipt->>'site_config_sha256'
               AND ruleset.ruleset_sha256 =
                   receipt->>'ruleset_sha256'
               AND writer.runtime_session_id =
                   receipt->>'runtime_session_id'
               AND writer.writer_generation =
                   (
                     receipt->>'runtime_writer_generation'
                   )::bigint
               AND writer.configuration_activation_generation =
                   active.activation_generation
               AND writer.issued_at =
                   (receipt->>'issued_at')::timestamptz
               AND history.issued_at =
                   (receipt->>'issued_at')::timestamptz
               AND history.receipt_sha256 = p_receipt_sha256
             FOR SHARE OF active, writer, history, config, ruleset;
            RETURN FOUND;
        EXCEPTION
            WHEN others THEN
                RETURN false;
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_get_runtime_claim_state(p_site_id text)
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            active public.active_pilot_configurations%ROWTYPE;
            writer public.runtime_writer_authorities%ROWTYPE;
            config public.site_config_revisions%ROWTYPE;
            ruleset public.camera_ruleset_revisions%ROWTYPE;
            rule_digests jsonb;
            rule_count integer;
        BEGIN
            IF p_site_id
                 !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '22023',
                    MESSAGE = 'runtime claim site is invalid';
            END IF;
            SELECT *
              INTO active
              FROM public.active_pilot_configurations
             WHERE site_id = p_site_id
             FOR SHARE;
            SELECT *
              INTO writer
              FROM public.runtime_writer_authorities
             WHERE site_id = active.site_id
               AND configuration_activation_generation =
                   active.activation_generation
             FOR SHARE;
            SELECT *
              INTO config
              FROM public.site_config_revisions
             WHERE site_id = active.site_id
               AND config_revision_id = active.config_revision_id
             FOR SHARE;
            SELECT *
              INTO ruleset
              FROM public.camera_ruleset_revisions
             WHERE site_id = active.site_id
               AND config_revision_id = active.config_revision_id
               AND ruleset_revision_id = active.ruleset_revision_id
             FOR SHARE;
            IF active.site_id IS NULL
               OR writer.site_id IS NULL
               OR config.config_revision_id IS NULL
               OR ruleset.ruleset_revision_id IS NULL
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'site has no exact active reviewed runtime authority';
            END IF;
            PERFORM 1
              FROM public.camera_rule_revisions AS rule
             WHERE rule.site_id = p_site_id
               AND rule.ruleset_revision_id =
                   active.ruleset_revision_id
             ORDER BY rule.rule_id
             FOR SHARE;
            SELECT
                count(*),
                jsonb_object_agg(
                    rule.rule_id,
                    rule.rule_revision_sha256
                    ORDER BY rule.rule_id
                )
              INTO rule_count, rule_digests
              FROM public.camera_rule_revisions AS rule
             WHERE rule.site_id = p_site_id
               AND rule.ruleset_revision_id =
                   active.ruleset_revision_id;
            IF rule_count NOT BETWEEN 1 AND 512 THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'active runtime authority has invalid rule membership';
            END IF;
            RETURN jsonb_build_object(
                'schema_version', 'runtime-claim-state.v1',
                'site_id', active.site_id,
                'activation_generation', active.activation_generation,
                'config_revision_id', active.config_revision_id,
                'site_config_sha256', config.config_sha256,
                'ruleset_revision_id', active.ruleset_revision_id,
                'ruleset_sha256', ruleset.ruleset_sha256,
                'rule_revision_digests', rule_digests,
                'current_runtime_session_id',
                    writer.runtime_session_id,
                'current_writer_generation', writer.writer_generation,
                'writer_configuration_activation_generation',
                    writer.configuration_activation_generation,
                'writer_issued_at', writer.issued_at
            );
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_claim_runtime_writer(
            receipt_canonical_json text,
            receipt_sha256 text
        )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            active public.active_pilot_configurations%ROWTYPE;
            writer public.runtime_writer_authorities%ROWTYPE;
            config public.site_config_revisions%ROWTYPE;
            ruleset public.camera_ruleset_revisions%ROWTYPE;
            prior public.runtime_writer_sessions%ROWTYPE;
            rule_digests jsonb;
            predicted_generation bigint;
            requested_issued_at timestamptz;
        BEGIN
            IF receipt_canonical_json IS NULL
               OR octet_length(receipt_canonical_json) > 131072
               OR receipt_sha256 !~ '^[0-9a-f]{64}$'
               OR encode(
                    sha256(convert_to(receipt_canonical_json, 'UTF8')),
                    'hex'
                  ) <> receipt_sha256
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime writer receipt digest is invalid';
            END IF;
            receipt := receipt_canonical_json::jsonb;
            IF (
                 SELECT count(*)
                   FROM jsonb_object_keys(receipt)
               ) <> 11
               OR NOT (
                    receipt ?& ARRAY[
                        'schema_version',
                        'site_id',
                        'runtime_session_id',
                        'runtime_writer_generation',
                        'configuration_activation_generation',
                        'config_revision_id',
                        'site_config_sha256',
                        'ruleset_revision_id',
                        'ruleset_sha256',
                        'rule_revision_digests',
                        'issued_at'
                    ]
               )
               OR receipt->>'schema_version'
                    <> 'runtime-writer-receipt.v1'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime writer receipt shape is invalid';
            END IF;
            requested_issued_at :=
                (receipt->>'issued_at')::timestamptz;

            SELECT *
              INTO active
              FROM public.active_pilot_configurations
             WHERE site_id = receipt->>'site_id'
             FOR UPDATE;
            SELECT *
              INTO writer
              FROM public.runtime_writer_authorities
             WHERE site_id = active.site_id
               AND configuration_activation_generation =
                   active.activation_generation
             FOR UPDATE;
            SELECT *
              INTO config
              FROM public.site_config_revisions
             WHERE site_id = active.site_id
               AND config_revision_id = active.config_revision_id
             FOR SHARE;
            SELECT *
              INTO ruleset
              FROM public.camera_ruleset_revisions
             WHERE site_id = active.site_id
               AND config_revision_id = active.config_revision_id
               AND ruleset_revision_id = active.ruleset_revision_id
             FOR SHARE;
            IF active.site_id IS NULL
               OR writer.site_id IS NULL
               OR config.config_revision_id IS NULL
               OR ruleset.ruleset_revision_id IS NULL
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime writer has no active authority';
            END IF;
            PERFORM 1
              FROM public.camera_rule_revisions AS rule
             WHERE rule.site_id = active.site_id
               AND rule.ruleset_revision_id =
                   active.ruleset_revision_id
             ORDER BY rule.rule_id
             FOR SHARE;
            SELECT jsonb_object_agg(
                       rule.rule_id,
                       rule.rule_revision_sha256
                       ORDER BY rule.rule_id
                   )
              INTO rule_digests
              FROM public.camera_rule_revisions AS rule
             WHERE rule.site_id = active.site_id
               AND rule.ruleset_revision_id =
                   active.ruleset_revision_id;
            IF rule_digests IS NULL
               OR rule_digests <> receipt->'rule_revision_digests'
               OR active.activation_generation <>
                    (
                      receipt
                      ->>'configuration_activation_generation'
                    )::bigint
               OR active.config_revision_id <>
                    receipt->>'config_revision_id'
               OR active.ruleset_revision_id <>
                    receipt->>'ruleset_revision_id'
               OR config.config_sha256 <>
                    receipt->>'site_config_sha256'
               OR ruleset.site_config_sha256 <>
                    receipt->>'site_config_sha256'
               OR ruleset.ruleset_sha256 <>
                    receipt->>'ruleset_sha256'
               OR writer.configuration_activation_generation <>
                    active.activation_generation
               OR requested_issued_at < writer.issued_at
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'runtime writer receipt does not match active authority';
            END IF;

            SELECT *
              INTO prior
              FROM public.runtime_writer_sessions
             WHERE runtime_session_id =
                   receipt->>'runtime_session_id'
             FOR UPDATE;
            IF writer.runtime_session_id =
                 receipt->>'runtime_session_id'
            THEN
                IF prior.runtime_session_id IS NULL
                   OR writer.writer_generation <>
                        (
                          receipt->>'runtime_writer_generation'
                        )::bigint
                   OR writer.issued_at <> requested_issued_at
                   OR prior.site_id <> active.site_id
                   OR prior.writer_generation <>
                        writer.writer_generation
                   OR prior.configuration_activation_generation <>
                        active.activation_generation
                   OR prior.issued_at <> requested_issued_at
                   OR prior.receipt_sha256 <> receipt_sha256
                   OR requested_issued_at >
                        CURRENT_TIMESTAMP + interval '5 minutes'
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23505',
                        MESSAGE =
                          'runtime writer replay conflicts with history';
                END IF;
                IF NOT public.pilot_runtime_receipt_is_current(
                    receipt_canonical_json,
                    receipt_sha256
                ) THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23514',
                        MESSAGE =
                          'runtime writer replay failed authority validation';
                END IF;
                RETURN receipt_sha256;
            END IF;
            IF prior.runtime_session_id IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505',
                    MESSAGE =
                      'retired runtime session cannot be reused';
            END IF;
            IF requested_issued_at NOT BETWEEN
                 CURRENT_TIMESTAMP - interval '5 minutes'
                 AND CURRENT_TIMESTAMP + interval '5 minutes'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'runtime writer issue time is outside server clock';
            END IF;
            predicted_generation :=
                writer.writer_generation
                + CASE
                    WHEN writer.runtime_session_id IS NULL THEN 0
                    ELSE 1
                  END;
            IF predicted_generation <>
                 (receipt->>'runtime_writer_generation')::bigint
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '40001',
                    MESSAGE =
                      'runtime writer generation changed during claim';
            END IF;

            UPDATE public.runtime_writer_authorities
               SET runtime_session_id =
                       receipt->>'runtime_session_id',
                   writer_generation = predicted_generation,
                   issued_at = requested_issued_at
             WHERE site_id = active.site_id;
            INSERT INTO public.runtime_writer_sessions (
                runtime_session_id,
                site_id,
                writer_generation,
                configuration_activation_generation,
                issued_at,
                receipt_sha256
            ) VALUES (
                receipt->>'runtime_session_id',
                active.site_id,
                predicted_generation,
                active.activation_generation,
                requested_issued_at,
                receipt_sha256
            );
            IF NOT public.pilot_runtime_receipt_is_current(
                receipt_canonical_json,
                receipt_sha256
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'runtime writer receipt failed post-claim validation';
            END IF;
            RETURN receipt_sha256;
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_get_runtime_configuration(
            receipt_canonical_json text,
            receipt_sha256 text
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            projection jsonb;
        BEGIN
            IF receipt_canonical_json IS NULL
               OR octet_length(receipt_canonical_json) > 131072
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '22023',
                    MESSAGE = 'runtime configuration receipt is oversized';
            END IF;
            receipt := receipt_canonical_json::jsonb;
            PERFORM 1
              FROM public.active_pilot_configurations AS active
              JOIN public.runtime_writer_authorities AS writer
                ON writer.site_id = active.site_id
              JOIN public.runtime_writer_sessions AS history
                ON history.site_id = active.site_id
               AND history.runtime_session_id =
                   writer.runtime_session_id
               AND history.writer_generation =
                   writer.writer_generation
               AND history.configuration_activation_generation =
                   writer.configuration_activation_generation
             WHERE active.site_id = receipt->>'site_id'
             FOR SHARE OF active, writer, history;
            IF NOT FOUND
               OR NOT public.pilot_runtime_receipt_is_current(
                    receipt_canonical_json,
                    receipt_sha256
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime configuration authority is retired';
            END IF;
            PERFORM 1
              FROM public.site_config_revisions AS config
              JOIN public.camera_ruleset_revisions AS ruleset
                ON ruleset.site_id = config.site_id
               AND ruleset.config_revision_id =
                   config.config_revision_id
             WHERE config.site_id = receipt->>'site_id'
               AND config.config_revision_id =
                   receipt->>'config_revision_id'
               AND ruleset.ruleset_revision_id =
                   receipt->>'ruleset_revision_id'
             FOR SHARE OF config, ruleset;
            PERFORM 1
              FROM public.camera_rule_revisions AS rule
             WHERE rule.site_id = receipt->>'site_id'
               AND rule.ruleset_revision_id =
                   receipt->>'ruleset_revision_id'
             ORDER BY rule.camera_id, rule.module, rule.rule_id,
                      rule.revision
             FOR SHARE;

            SELECT jsonb_build_object(
                       'schema_version',
                         'runtime-configuration-projection.v1',
                       'active', to_jsonb(active),
                       'writer', to_jsonb(writer),
                       'writer_session', to_jsonb(history),
                       'config', to_jsonb(config),
                       'ruleset', to_jsonb(ruleset),
                       'rules',
                         (
                           SELECT jsonb_agg(
                                    to_jsonb(rule)
                                    ORDER BY
                                      rule.camera_id,
                                      rule.module,
                                      rule.rule_id,
                                      rule.revision
                                  )
                             FROM public.camera_rule_revisions AS rule
                            WHERE rule.site_id = active.site_id
                              AND rule.ruleset_revision_id =
                                  active.ruleset_revision_id
                         )
                   )
              INTO projection
              FROM public.active_pilot_configurations AS active
              JOIN public.runtime_writer_authorities AS writer
                ON writer.site_id = active.site_id
              JOIN public.runtime_writer_sessions AS history
                ON history.site_id = active.site_id
               AND history.runtime_session_id =
                   writer.runtime_session_id
               AND history.writer_generation =
                   writer.writer_generation
               AND history.configuration_activation_generation =
                   writer.configuration_activation_generation
              JOIN public.site_config_revisions AS config
                ON config.site_id = active.site_id
               AND config.config_revision_id =
                   active.config_revision_id
              JOIN public.camera_ruleset_revisions AS ruleset
                ON ruleset.site_id = active.site_id
               AND ruleset.config_revision_id =
                   active.config_revision_id
               AND ruleset.ruleset_revision_id =
                   active.ruleset_revision_id
             WHERE active.site_id = receipt->>'site_id';
            IF projection IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'runtime configuration projection is incomplete';
            END IF;
            RETURN projection;
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_get_runtime_event(
            receipt_canonical_json text,
            receipt_sha256 text,
            p_event_id uuid
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            event_payload jsonb;
        BEGIN
            IF receipt_canonical_json IS NULL
               OR octet_length(receipt_canonical_json) > 131072
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '22023',
                    MESSAGE = 'runtime event receipt is oversized';
            END IF;
            receipt := receipt_canonical_json::jsonb;
            IF NOT public.pilot_runtime_receipt_is_current(
                receipt_canonical_json,
                receipt_sha256
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'runtime event reader is retired';
            END IF;
            SELECT
                (
                  to_jsonb(candidate)
                  - ARRAY['dedupe_key', 'transition_history', 'created_at']
                )
                || jsonb_build_object(
                     'transition_history',
                     to_jsonb(
                       string_to_array(
                         candidate.transition_history,
                         '>'
                       )
                     )
                   )
              INTO event_payload
              FROM public.candidate_events AS candidate
              JOIN public.candidate_event_provenance AS provenance
                ON provenance.event_id = candidate.event_id
              JOIN public.cameras AS camera
                ON camera.camera_id = candidate.camera_id
              JOIN public.camera_epoch_authorities AS epoch
                ON epoch.site_id = provenance.site_id
               AND epoch.camera_id = candidate.camera_id
             WHERE candidate.event_id = p_event_id::text
               AND camera.site_id = receipt->>'site_id'
               AND provenance.site_id = receipt->>'site_id'
               AND provenance.runtime_session_id =
                   receipt->>'runtime_session_id'
               AND provenance.runtime_writer_generation =
                   (
                     receipt->>'runtime_writer_generation'
                   )::bigint
               AND provenance.configuration_activation_generation =
                   (
                     receipt
                     ->>'configuration_activation_generation'
                   )::bigint
               AND provenance.ruleset_revision_id =
                   receipt->>'ruleset_revision_id'
               AND provenance.ruleset_sha256 =
                   receipt->>'ruleset_sha256'
               AND provenance.site_config_sha256 =
                   receipt->>'site_config_sha256'
               AND provenance.rule_revision_sha256 =
                   receipt->'rule_revision_digests'
                     ->>provenance.rule_id
               AND epoch.source_epoch = provenance.source_epoch
               AND epoch.runtime_session_id =
                   provenance.runtime_session_id
               AND epoch.writer_generation =
                   provenance.runtime_writer_generation
               AND epoch.configuration_activation_generation =
                   provenance.configuration_activation_generation
             FOR SHARE OF candidate, provenance, epoch;
            IF event_payload IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'runtime event lacks exact current provenance';
            END IF;
            RETURN event_payload;
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_activate_runtime_camera_epoch(
            receipt_canonical_json text,
            receipt_sha256 text,
            p_camera_id text,
            p_source_epoch uuid,
            p_expected_source_epoch uuid,
            p_activated_at timestamptz
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            current_epoch public.camera_epoch_authorities%ROWTYPE;
            prior_epoch public.camera_epoch_history%ROWTYPE;
            actual_source_epoch uuid;
            current_matches_writer boolean;
        BEGIN
            IF receipt_canonical_json IS NULL
               OR octet_length(receipt_canonical_json) > 131072
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '22023',
                    MESSAGE = 'camera epoch receipt is oversized';
            END IF;
            receipt := receipt_canonical_json::jsonb;
            IF p_camera_id
                 !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
               OR p_activated_at IS NULL
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'camera epoch writer authority is invalid';
            END IF;
            PERFORM 1
              FROM public.active_pilot_configurations AS active
              JOIN public.runtime_writer_authorities AS writer
                ON writer.site_id = active.site_id
             WHERE active.site_id = receipt->>'site_id'
             FOR UPDATE OF active, writer;
            IF NOT FOUND
               OR NOT public.pilot_runtime_receipt_is_current(
                    receipt_canonical_json,
                    receipt_sha256
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'camera epoch writer authority is invalid';
            END IF;
            PERFORM 1
              FROM public.cameras AS camera
             WHERE camera.site_id = receipt->>'site_id'
               AND camera.camera_id = p_camera_id
             FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'camera does not belong to writer site';
            END IF;
            SELECT *
              INTO current_epoch
              FROM public.camera_epoch_authorities
             WHERE camera_id = p_camera_id
             FOR UPDATE;
            current_matches_writer :=
                current_epoch.camera_id IS NOT NULL
                AND current_epoch.site_id = receipt->>'site_id'
                AND current_epoch.runtime_session_id =
                    receipt->>'runtime_session_id'
                AND current_epoch.writer_generation =
                    (
                      receipt->>'runtime_writer_generation'
                    )::bigint
                AND current_epoch.configuration_activation_generation =
                    (
                      receipt
                      ->>'configuration_activation_generation'
                    )::bigint;
            actual_source_epoch := CASE
                WHEN current_matches_writer
                THEN current_epoch.source_epoch::uuid
                ELSE NULL
            END;
            SELECT *
              INTO prior_epoch
              FROM public.camera_epoch_history
             WHERE camera_id = p_camera_id
               AND source_epoch = p_source_epoch::text
             FOR UPDATE;
            IF current_matches_writer
               AND actual_source_epoch = p_source_epoch
               AND prior_epoch.camera_id IS NOT NULL
            THEN
                IF prior_epoch.previous_source_epoch
                        IS DISTINCT FROM
                        p_expected_source_epoch::text
                   OR prior_epoch.site_id <> receipt->>'site_id'
                   OR prior_epoch.runtime_session_id <>
                        receipt->>'runtime_session_id'
                   OR prior_epoch.writer_generation <>
                        (
                          receipt->>'runtime_writer_generation'
                        )::bigint
                   OR prior_epoch.configuration_activation_generation <>
                        (
                          receipt
                          ->>'configuration_activation_generation'
                        )::bigint
                   OR prior_epoch.activated_at <> p_activated_at
                   OR p_activated_at >
                        CURRENT_TIMESTAMP + interval '5 minutes'
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23505',
                        MESSAGE =
                          'camera epoch replay conflicts with authority';
                END IF;
                RETURN true;
            END IF;
            IF prior_epoch.camera_id IS NOT NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505',
                    MESSAGE = 'retired camera epoch cannot be reused';
            END IF;
            IF p_activated_at NOT BETWEEN
                 CURRENT_TIMESTAMP - interval '5 minutes'
                 AND CURRENT_TIMESTAMP + interval '5 minutes'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'camera epoch time is outside server clock';
            END IF;
            IF actual_source_epoch IS DISTINCT FROM
                 p_expected_source_epoch
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '40001',
                    MESSAGE = 'camera epoch CAS is stale';
            END IF;
            IF p_activated_at <
                 (receipt->>'issued_at')::timestamptz
               OR (
                    current_epoch.camera_id IS NOT NULL
                    AND p_activated_at < current_epoch.activated_at
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'camera epoch time cannot regress';
            END IF;
            INSERT INTO public.camera_epoch_history (
                camera_id,
                source_epoch,
                previous_source_epoch,
                site_id,
                runtime_session_id,
                writer_generation,
                configuration_activation_generation,
                activated_at
            ) VALUES (
                p_camera_id,
                p_source_epoch::text,
                p_expected_source_epoch::text,
                receipt->>'site_id',
                receipt->>'runtime_session_id',
                (receipt->>'runtime_writer_generation')::bigint,
                (
                  receipt
                  ->>'configuration_activation_generation'
                )::bigint,
                p_activated_at
            );
            INSERT INTO public.camera_epoch_authorities (
                camera_id,
                site_id,
                source_epoch,
                runtime_session_id,
                writer_generation,
                configuration_activation_generation,
                activated_at
            ) VALUES (
                p_camera_id,
                receipt->>'site_id',
                p_source_epoch::text,
                receipt->>'runtime_session_id',
                (receipt->>'runtime_writer_generation')::bigint,
                (
                  receipt
                  ->>'configuration_activation_generation'
                )::bigint,
                p_activated_at
            )
            ON CONFLICT (camera_id) DO UPDATE
               SET site_id = EXCLUDED.site_id,
                   source_epoch = EXCLUDED.source_epoch,
                   runtime_session_id = EXCLUDED.runtime_session_id,
                   writer_generation = EXCLUDED.writer_generation,
                   configuration_activation_generation =
                       EXCLUDED.configuration_activation_generation,
                   activated_at = EXCLUDED.activated_at;
            RETURN true;
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_set_runtime_candidate_evidence_status(
            receipt_canonical_json text,
            receipt_sha256 text,
            p_event_id uuid,
            p_target text
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            candidate public.candidate_events%ROWTYPE;
            payload jsonb;
        BEGIN
            IF receipt_canonical_json IS NULL
               OR octet_length(receipt_canonical_json) > 131072
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '22023',
                    MESSAGE =
                      'candidate evidence receipt is oversized';
            END IF;
            receipt := receipt_canonical_json::jsonb;
            IF p_target NOT IN ('pending', 'failed')
               OR NOT public.pilot_runtime_receipt_is_current(
                    receipt_canonical_json,
                    receipt_sha256
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'candidate evidence status authority is invalid';
            END IF;
            SELECT candidate_row.*
              INTO candidate
              FROM public.candidate_events AS candidate_row
              JOIN public.candidate_event_provenance AS provenance
                ON provenance.event_id = candidate_row.event_id
              JOIN public.cameras AS camera
                ON camera.camera_id = candidate_row.camera_id
              JOIN public.camera_epoch_authorities AS epoch
                ON epoch.site_id = provenance.site_id
               AND epoch.camera_id = candidate_row.camera_id
              JOIN public.camera_rule_revisions AS rule
                ON rule.site_id = provenance.site_id
               AND rule.ruleset_revision_id =
                   provenance.ruleset_revision_id
               AND rule.rule_id = provenance.rule_id
             WHERE candidate_row.event_id = p_event_id::text
               AND camera.site_id = receipt->>'site_id'
               AND provenance.site_id = receipt->>'site_id'
               AND provenance.runtime_session_id =
                   receipt->>'runtime_session_id'
               AND provenance.runtime_writer_generation =
                   (
                     receipt->>'runtime_writer_generation'
                   )::bigint
               AND provenance.configuration_activation_generation =
                   (
                     receipt
                     ->>'configuration_activation_generation'
                   )::bigint
               AND provenance.ruleset_revision_id =
                   receipt->>'ruleset_revision_id'
               AND provenance.ruleset_sha256 =
                   receipt->>'ruleset_sha256'
               AND provenance.site_config_sha256 =
                   receipt->>'site_config_sha256'
               AND provenance.rule_revision_sha256 =
                   receipt->'rule_revision_digests'
                     ->>provenance.rule_id
               AND epoch.source_epoch = provenance.source_epoch
               AND epoch.runtime_session_id =
                   provenance.runtime_session_id
               AND epoch.writer_generation =
                   provenance.runtime_writer_generation
               AND epoch.configuration_activation_generation =
                   provenance.configuration_activation_generation
               AND rule.enabled
               AND rule.camera_id = candidate_row.camera_id
               AND rule.module = candidate_row.module
               AND rule.model_artifact_id =
                   candidate_row.model_artifact_id
               AND rule.gate_mode = candidate_row.gate_mode
               AND rule.rule_revision_sha256 =
                   provenance.rule_revision_sha256
               AND candidate_row.review_status = 'candidate'
               AND candidate_row.transition_history =
                   'observation>candidate'
             FOR UPDATE OF candidate_row, epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'candidate lacks current writer provenance and epoch';
            END IF;
            IF (
                 p_target = 'pending'
                 AND candidate.evidence_status
                     NOT IN ('unavailable', 'pending')
               )
               OR (
                 p_target = 'failed'
                 AND candidate.evidence_status
                     NOT IN ('unavailable', 'pending', 'failed')
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '40001',
                    MESSAGE =
                      'candidate evidence status transition is stale';
            END IF;
            UPDATE public.candidate_events
               SET evidence_status = p_target
             WHERE event_id = p_event_id::text;
            SELECT
                (
                  to_jsonb(updated)
                  - ARRAY['dedupe_key', 'transition_history', 'created_at']
                )
                || jsonb_build_object(
                     'transition_history',
                     to_jsonb(
                       string_to_array(
                         updated.transition_history,
                         '>'
                       )
                     )
                   )
              INTO payload
              FROM public.candidate_events AS updated
             WHERE updated.event_id = p_event_id::text;
            RETURN payload;
        END;
        $$
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION pilot_finalize_runtime_evidence(
            receipt_canonical_json text,
            receipt_sha256 text,
            p_evidence jsonb
        )
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            receipt jsonb;
            candidate public.candidate_events%ROWTYPE;
            stored public.evidence%ROWTYPE;
            target text;
            requested_start timestamptz;
            requested_end timestamptz;
            material_matches boolean;
        BEGIN
            IF receipt_canonical_json IS NULL
               OR octet_length(receipt_canonical_json) > 131072
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '22023',
                    MESSAGE = 'terminal evidence receipt is oversized';
            END IF;
            receipt := receipt_canonical_json::jsonb;
            IF (
                 SELECT count(*)
                   FROM jsonb_object_keys(p_evidence)
               ) <> 10
               OR NOT (
                    p_evidence ?& ARRAY[
                        'schema_version',
                        'evidence_id',
                        'event_id',
                        'object_key',
                        'sha256',
                        'codec',
                        'start_at',
                        'end_at',
                        'source_reference',
                        'status'
                    ]
               )
               OR jsonb_typeof(
                    p_evidence->'schema_version'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'evidence_id'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'event_id'
                  ) <> 'string'
               OR jsonb_typeof(p_evidence->'object_key') <> 'string'
               OR jsonb_typeof(
                    p_evidence->'sha256'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'codec'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'start_at'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'end_at'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'source_reference'
                  ) <> 'string'
               OR jsonb_typeof(
                    p_evidence->'status'
                  ) <> 'string'
               OR p_evidence->>'schema_version' <> 'evidence-work.v1'
               OR p_evidence->>'evidence_id'
                    !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
               OR p_evidence->>'event_id'
                    !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
               OR p_evidence->>'sha256' !~ '^[0-9a-f]{64}$'
               OR p_evidence->>'codec' NOT IN ('h264', 'h265')
               OR p_evidence->>'status' NOT IN ('ready', 'failed')
               OR length(p_evidence->>'object_key')
                    NOT BETWEEN 1 AND 1024
               OR length(p_evidence->>'source_reference')
                    NOT BETWEEN 1 AND 2048
               OR NOT public.pilot_runtime_receipt_is_current(
                    receipt_canonical_json,
                    receipt_sha256
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'terminal evidence work is invalid';
            END IF;
            target := p_evidence->>'status';
            requested_start :=
                (p_evidence->>'start_at')::timestamptz;
            requested_end :=
                (p_evidence->>'end_at')::timestamptz;
            IF requested_end <= requested_start
               OR requested_end - requested_start
                    > interval '10 seconds'
               OR (
                    target = 'ready'
                    AND requested_end - requested_start
                        < interval '4 seconds'
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'terminal evidence violates bounded clip duration';
            END IF;

            SELECT candidate_row.*
              INTO candidate
              FROM public.candidate_events AS candidate_row
              JOIN public.candidate_event_provenance AS provenance
                ON provenance.event_id = candidate_row.event_id
              JOIN public.cameras AS camera
                ON camera.camera_id = candidate_row.camera_id
              JOIN public.camera_epoch_authorities AS epoch
                ON epoch.site_id = provenance.site_id
               AND epoch.camera_id = candidate_row.camera_id
              JOIN public.camera_rule_revisions AS rule
                ON rule.site_id = provenance.site_id
               AND rule.ruleset_revision_id =
                   provenance.ruleset_revision_id
               AND rule.rule_id = provenance.rule_id
             WHERE candidate_row.event_id = p_evidence->>'event_id'
               AND camera.site_id = receipt->>'site_id'
               AND provenance.site_id = receipt->>'site_id'
               AND provenance.runtime_session_id =
                   receipt->>'runtime_session_id'
               AND provenance.runtime_writer_generation =
                   (
                     receipt->>'runtime_writer_generation'
                   )::bigint
               AND provenance.configuration_activation_generation =
                   (
                     receipt
                     ->>'configuration_activation_generation'
                   )::bigint
               AND provenance.ruleset_revision_id =
                   receipt->>'ruleset_revision_id'
               AND provenance.ruleset_sha256 =
                   receipt->>'ruleset_sha256'
               AND provenance.site_config_sha256 =
                   receipt->>'site_config_sha256'
               AND provenance.rule_revision_sha256 =
                   receipt->'rule_revision_digests'
                     ->>provenance.rule_id
               AND epoch.source_epoch = provenance.source_epoch
               AND epoch.runtime_session_id =
                   provenance.runtime_session_id
               AND epoch.writer_generation =
                   provenance.runtime_writer_generation
               AND epoch.configuration_activation_generation =
                   provenance.configuration_activation_generation
               AND rule.enabled
               AND rule.camera_id = candidate_row.camera_id
               AND rule.module = candidate_row.module
               AND rule.model_artifact_id =
                   candidate_row.model_artifact_id
               AND rule.gate_mode = candidate_row.gate_mode
               AND rule.rule_revision_sha256 =
                   provenance.rule_revision_sha256
               AND candidate_row.review_status = 'candidate'
               AND candidate_row.transition_history =
                   'observation>candidate'
             FOR UPDATE OF candidate_row, epoch;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'evidence event lacks current provenance and epoch';
            END IF;
            IF (p_evidence->>'object_key') <>
                    (
                      'events/' || (p_evidence->>'event_id')
                      || '.mp4'
                    )
               OR (p_evidence->>'source_reference') <>
                    (
                      'nvr://' || (receipt->>'site_id') || '/'
                      || candidate.camera_id
                    )
               OR requested_start > candidate.opened_at
               OR requested_end < candidate.last_seen_at
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE =
                      'terminal evidence escaped its exact event scope';
            END IF;
            SELECT *
              INTO stored
              FROM public.evidence
             WHERE evidence_id = p_evidence->>'evidence_id'
                OR object_key = p_evidence->>'object_key'
             FOR UPDATE;
            material_matches :=
                stored.evidence_id IS NOT NULL
                AND stored.evidence_id =
                    p_evidence->>'evidence_id'
                AND stored.event_id = p_evidence->>'event_id'
                AND stored.object_key = p_evidence->>'object_key'
                AND stored.sha256 = p_evidence->>'sha256'
                AND stored.codec = p_evidence->>'codec'
                AND stored.start_at = requested_start
                AND stored.end_at = requested_end
                AND stored.source_reference =
                    p_evidence->>'source_reference';
            IF candidate.evidence_status = 'ready'
               AND target = 'failed'
            THEN
                IF NOT material_matches THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23505',
                        MESSAGE =
                          'failed replay conflicts with ready evidence';
                END IF;
                RETURN true;
            END IF;
            IF (
                 candidate.evidence_status = 'pending'
                 AND target NOT IN ('ready', 'failed')
               )
               OR (
                 candidate.evidence_status = 'failed'
                 AND target NOT IN ('failed', 'ready')
               )
               OR (
                 candidate.evidence_status = 'ready'
                 AND target <> 'ready'
               )
               OR candidate.evidence_status NOT IN (
                    'pending', 'failed', 'ready'
               )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '40001',
                    MESSAGE =
                      'candidate terminal evidence transition is stale';
            END IF;
            IF stored.evidence_id IS NULL THEN
                INSERT INTO public.evidence (
                    evidence_id,
                    event_id,
                    object_key,
                    sha256,
                    codec,
                    start_at,
                    end_at,
                    source_reference,
                    status,
                    created_at
                ) VALUES (
                    p_evidence->>'evidence_id',
                    p_evidence->>'event_id',
                    p_evidence->>'object_key',
                    p_evidence->>'sha256',
                    p_evidence->>'codec',
                    requested_start,
                    requested_end,
                    p_evidence->>'source_reference',
                    target,
                    CURRENT_TIMESTAMP
                );
            ELSE
                IF NOT material_matches
                   OR (
                        stored.status = 'ready'
                        AND target <> 'ready'
                   )
                   OR stored.status NOT IN (
                        'pending', 'failed', 'ready'
                   )
                THEN
                    RAISE EXCEPTION USING
                        ERRCODE = '23505',
                        MESSAGE =
                          'evidence identity or transition conflicts';
                END IF;
                UPDATE public.evidence
                   SET status = target
                 WHERE evidence_id = stored.evidence_id;
            END IF;
            UPDATE public.candidate_events
               SET evidence_status = target
             WHERE event_id = p_evidence->>'event_id';
            RETURN true;
        END;
        $$
        """
    )
    op.execute(
        """
        WITH ranked AS (
          SELECT health_sample_id,
                 ROW_NUMBER() OVER (
                   PARTITION BY camera_id
                   ORDER BY observed_at DESC, health_sample_id DESC
                 ) AS retention_rank
            FROM public.camera_health_samples
        )
        DELETE FROM public.camera_health_samples AS health
         USING ranked
         WHERE health.health_sample_id = ranked.health_sample_id
           AND ranked.retention_rank > 1
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_camera_health_latest_per_camera
          ON public.camera_health_samples (camera_id)
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_upsert_camera_health_sample(
          p_site_id text,
          p_sample jsonb
        )
        RETURNS bigint
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          row_id bigint;
          observed_at timestamptz;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_sample IS NULL
             OR jsonb_typeof(p_sample) <> 'object'
             OR ARRAY(
                  SELECT entry.key
                    FROM jsonb_object_keys(p_sample) AS entry(key)
                   ORDER BY entry.key
                ) <> ARRAY[
                  'camera_id',
                  'degraded_reason',
                  'dropped_samples',
                  'last_frame_at',
                  'observed_at',
                  'reconnect_count',
                  'runtime_session_id',
                  'state'
                ]
             OR p_sample->>'camera_id'
                  !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_sample->>'runtime_session_id'
                  !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_sample->>'state' NOT IN (
                  'starting',
                  'online',
                  'degraded',
                  'offline',
                  'reconnecting'
                )
             OR jsonb_typeof(p_sample->'observed_at') <> 'string'
             OR (
                  p_sample->'last_frame_at' <> 'null'::jsonb
                  AND jsonb_typeof(p_sample->'last_frame_at') <>
                      'string'
                )
             OR jsonb_typeof(p_sample->'reconnect_count') <> 'number'
             OR p_sample->>'reconnect_count' !~ '^[0-9]+$'
             OR jsonb_typeof(p_sample->'dropped_samples') <> 'number'
             OR p_sample->>'dropped_samples' !~ '^[0-9]+$'
             OR (
                  p_sample->'degraded_reason' <> 'null'::jsonb
                  AND (
                    jsonb_typeof(p_sample->'degraded_reason') <>
                      'string'
                    OR length(p_sample->>'degraded_reason') > 2000
                  )
                )
          THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'camera health sample is invalid';
          END IF;
          observed_at := (p_sample->>'observed_at')::timestamptz;
          IF observed_at NOT BETWEEN
               clock_timestamp() - interval '5 minutes'
               AND clock_timestamp() + interval '5 minutes'
          THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'camera health sample time is invalid';
          END IF;

          INSERT INTO public.camera_health_samples (
            camera_id,
            runtime_session_id,
            observed_at,
            state,
            last_frame_at,
            reconnect_count,
            dropped_samples,
            degraded_reason
          )
          SELECT
            camera.camera_id,
            p_sample->>'runtime_session_id',
            observed_at,
            p_sample->>'state',
            (p_sample->>'last_frame_at')::timestamptz,
            (p_sample->>'reconnect_count')::integer,
            (p_sample->>'dropped_samples')::integer,
            p_sample->>'degraded_reason'
          FROM public.cameras AS camera
          JOIN public.active_pilot_configurations AS active
            ON active.site_id = camera.site_id
          JOIN public.site_config_revisions AS config
            ON config.site_id = active.site_id
           AND config.config_revision_id = active.config_revision_id
          WHERE camera.camera_id = p_sample->>'camera_id'
            AND camera.site_id = p_site_id
            AND camera.enabled
            AND jsonb_typeof(
                  config.canonical_config
                  #> '{ready_to_start,feeds}'
                ) = 'array'
            AND jsonb_array_length(
                  config.canonical_config
                  #> '{ready_to_start,feeds}'
                ) = 20
            AND EXISTS (
              SELECT 1
                FROM jsonb_array_elements(
                       config.canonical_config
                       #> '{ready_to_start,feeds}'
                     ) AS feed
               WHERE feed->>'camera_id' = camera.camera_id
            )
          ON CONFLICT (camera_id)
          DO UPDATE SET
            runtime_session_id = EXCLUDED.runtime_session_id,
            observed_at = EXCLUDED.observed_at,
            state = EXCLUDED.state,
            last_frame_at = EXCLUDED.last_frame_at,
            reconnect_count = EXCLUDED.reconnect_count,
            dropped_samples = EXCLUDED.dropped_samples,
            degraded_reason = EXCLUDED.degraded_reason
          WHERE public.camera_health_samples.observed_at <=
                EXCLUDED.observed_at
          RETURNING health_sample_id INTO row_id;
          IF row_id IS NULL THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'camera health sample is stale or unauthorized';
          END IF;
          RETURN row_id;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION pilot_prune_operational_metadata(
          p_site_id text,
          p_cutoff_at timestamptz,
          p_limit integer
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          metadata_retention_days integer;
          effective_cutoff timestamptz;
          health_samples_pruned integer;
          observations_pruned integer;
        BEGIN
          IF p_site_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
             OR p_cutoff_at IS NULL
             OR p_limit IS NULL
             OR NOT (p_limit BETWEEN 1 AND 1000) THEN
            RAISE EXCEPTION USING
              ERRCODE = '22023',
              MESSAGE = 'operational metadata prune is invalid';
          END IF;
          SELECT (
                   config.canonical_config #>>
                   '{storage,retention,metadata_retention_days}'
                 )::integer
            INTO metadata_retention_days
            FROM public.active_pilot_configurations AS active
            JOIN public.site_config_revisions AS config
              ON config.config_revision_id = active.config_revision_id
             AND config.site_id = active.site_id
           WHERE active.site_id = p_site_id
           FOR SHARE OF config;
          IF metadata_retention_days IS NULL
             OR NOT (metadata_retention_days BETWEEN 1 AND 365) THEN
            RAISE EXCEPTION USING
              ERRCODE = '23514',
              MESSAGE = 'active metadata retention policy is unavailable';
          END IF;
          effective_cutoff := LEAST(
            p_cutoff_at,
            clock_timestamp() - make_interval(
              days => metadata_retention_days
            )
          );

          WITH selected AS (
            SELECT health.health_sample_id
              FROM public.camera_health_samples AS health
              JOIN public.cameras AS camera
                ON camera.camera_id = health.camera_id
             WHERE camera.site_id = p_site_id
               AND health.observed_at < effective_cutoff
             ORDER BY health.observed_at, health.health_sample_id
             LIMIT p_limit
             FOR UPDATE OF health SKIP LOCKED
          ),
          deleted AS (
            DELETE FROM public.camera_health_samples AS health
             USING selected
             WHERE health.health_sample_id = selected.health_sample_id
             RETURNING health.health_sample_id
          )
          SELECT count(*)::integer
            INTO health_samples_pruned
            FROM deleted;

          WITH selected AS (
            SELECT observation.observation_id
              FROM public.observations AS observation
              JOIN public.cameras AS camera
                ON camera.camera_id = observation.camera_id
             WHERE camera.site_id = p_site_id
               AND observation.received_at < effective_cutoff
             ORDER BY observation.received_at,
                      observation.observation_id
             LIMIT p_limit
             FOR UPDATE OF observation SKIP LOCKED
          ),
          deleted AS (
            DELETE FROM public.observations AS observation
             USING selected
             WHERE observation.observation_id =
                   selected.observation_id
             RETURNING observation.observation_id
          )
          SELECT count(*)::integer
            INTO observations_pruned
            FROM deleted;

          RETURN jsonb_build_object(
            'health_samples', health_samples_pruned,
            'observations', observations_pruned
          );
        END;
        $$
        """
    )


def _apply_postgresql_runtime_grants() -> None:
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_upsert_camera_health_sample(text, jsonb)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_get_active_site_config_sha256(text)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_guard_storage_reconfiguration()
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_runtime_receipt_is_current(text, text)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_get_runtime_claim_state(text)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_claim_runtime_writer(text, text)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_get_runtime_configuration(text, text)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_get_runtime_event(text, text, uuid)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_activate_runtime_camera_epoch(
            text, text, text, uuid, uuid, timestamptz
          )
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_set_runtime_candidate_evidence_status(
            text, text, uuid, text
          )
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_finalize_runtime_evidence(text, text, jsonb)
          FROM PUBLIC
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION
          pilot_prune_operational_metadata(
            text, timestamptz, integer
          )
          FROM PUBLIC
        """
    )
    op.execute(
        """
        DO $$
        DECLARE
          runtime_is_unsafe boolean;
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_api'
          ) THEN
            REVOKE INSERT, UPDATE, DELETE
              ON TABLE public.camera_health_samples
              FROM kuzet_api;
            REVOKE INSERT ON TABLE public.observations
              FROM kuzet_api;
            REVOKE ALL ON SEQUENCE
              public.camera_health_samples_health_sample_id_seq
              FROM kuzet_api;
            GRANT EXECUTE ON FUNCTION
              pilot_upsert_camera_health_sample(text, jsonb)
              TO kuzet_api;
          END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_runtime'
          ) THEN
            SELECT role.rolsuper
                   OR role.rolcreatedb
                   OR role.rolcreaterole
                   OR role.rolinherit
                   OR role.rolreplication
                   OR role.rolbypassrls
                   OR EXISTS (
                     SELECT 1
                       FROM pg_auth_members AS membership
                      WHERE membership.member = role.oid
                   )
                   OR role.oid IN (
                     SELECT relation.relowner
                       FROM pg_class AS relation
                      WHERE relation.oid IN (
                        'public.sites'::regclass,
                        'public.cameras'::regclass,
                        'public.model_artifacts'::regclass,
                        'public.site_config_revisions'::regclass,
                        'public.camera_ruleset_revisions'::regclass,
                        'public.camera_rule_revisions'::regclass,
                        'public.configuration_activations'::regclass,
                        'public.active_pilot_configurations'::regclass,
                        'public.runtime_writer_authorities'::regclass,
                        'public.runtime_writer_sessions'::regclass,
                        'public.camera_epoch_authorities'::regclass,
                        'public.camera_epoch_history'::regclass,
                        'public.legacy_candidate_imports'::regclass,
                        'public.candidate_events'::regclass,
                        'public.candidate_event_provenance'::regclass,
                        'public.evidence'::regclass,
                        'public.preview_publications'::regclass,
                        'public.preview_access_receipts'::regclass
                      )
                   )
              INTO runtime_is_unsafe
              FROM pg_roles AS role
             WHERE role.rolname = 'kuzet_runtime';
            IF runtime_is_unsafe THEN
              RAISE EXCEPTION
                'kuzet_runtime must be isolated, unprivileged, and non-owner';
            END IF;
            REVOKE CREATE ON SCHEMA public FROM kuzet_runtime;
            EXECUTE
              'REVOKE ALL ON TABLE '
              'public.sites, public.cameras, public.model_artifacts, '
              'public.site_config_revisions, '
              'public.camera_ruleset_revisions, '
              'public.camera_rule_revisions, '
              'public.configuration_activations, '
              'public.active_pilot_configurations, '
              'public.runtime_writer_authorities, '
              'public.runtime_writer_sessions, '
              'public.camera_epoch_authorities, '
              'public.camera_epoch_history, '
              'public.legacy_candidate_imports, '
              'public.candidate_events, '
              'public.candidate_event_provenance, '
              'public.evidence, '
              'public.preview_publications, '
              'public.preview_access_receipts '
              'FROM kuzet_runtime';
            GRANT USAGE ON SCHEMA public TO kuzet_runtime;
            GRANT EXECUTE ON FUNCTION
              pilot_get_runtime_claim_state(text),
              pilot_claim_runtime_writer(text, text),
              pilot_get_runtime_configuration(text, text),
              pilot_get_runtime_event(text, text, uuid),
              pilot_activate_runtime_camera_epoch(
                text, text, text, uuid, uuid, timestamptz
              ),
              pilot_set_runtime_candidate_evidence_status(
                text, text, uuid, text
              ),
              pilot_finalize_runtime_evidence(text, text, jsonb),
              pilot_ingest_candidate(jsonb, jsonb),
              pilot_get_active_site_config_sha256(text),
              pilot_get_preview_object_context(text, uuid, uuid, uuid),
              pilot_prepare_preview_publication(jsonb),
              pilot_finalize_preview_receipt(jsonb, jsonb)
              TO kuzet_runtime;
          END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_retention'
          ) THEN
            GRANT EXECUTE ON FUNCTION
              pilot_get_active_site_config_sha256(text),
              pilot_prune_operational_metadata(
                text, timestamptz, integer
              )
              TO kuzet_retention;
          END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        DROP TRIGGER IF EXISTS
          trg_configuration_activation_storage_guard
          ON configuration_activations
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS
          pilot_guard_storage_reconfiguration()
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_api'
          ) THEN
            REVOKE EXECUTE ON FUNCTION
              pilot_upsert_camera_health_sample(text, jsonb)
              FROM kuzet_api;
            GRANT INSERT ON TABLE
              public.camera_health_samples,
              public.observations
              TO kuzet_api;
            GRANT USAGE, SELECT ON SEQUENCE
              public.camera_health_samples_health_sample_id_seq
              TO kuzet_api;
          END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_runtime'
          ) THEN
            REVOKE EXECUTE ON FUNCTION
              pilot_get_runtime_claim_state(text),
              pilot_claim_runtime_writer(text, text),
              pilot_get_runtime_configuration(text, text),
              pilot_get_runtime_event(text, text, uuid),
              pilot_activate_runtime_camera_epoch(
                text, text, text, uuid, uuid, timestamptz
              ),
              pilot_set_runtime_candidate_evidence_status(
                text, text, uuid, text
              ),
              pilot_finalize_runtime_evidence(text, text, jsonb)
              FROM kuzet_runtime;
          END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_retention'
          ) THEN
            REVOKE EXECUTE ON FUNCTION
              pilot_get_active_site_config_sha256(text),
              pilot_prune_operational_metadata(
                text, timestamptz, integer
              )
              FROM kuzet_retention;
          END IF;
        END
        $$;
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS
          pilot_upsert_camera_health_sample(text, jsonb)
        """
    )
    op.execute(
        """
        DROP INDEX IF EXISTS uq_camera_health_latest_per_camera
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_prune_operational_metadata(
          text, timestamptz, integer
        )
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_finalize_runtime_evidence(
          text, text, jsonb
        )
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_set_runtime_candidate_evidence_status(
          text, text, uuid, text
        )
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_activate_runtime_camera_epoch(
          text, text, text, uuid, uuid, timestamptz
        )
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_get_runtime_event(
          text, text, uuid
        )
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_get_runtime_configuration(
          text, text
        )
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_claim_runtime_writer(text, text)
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS pilot_get_runtime_claim_state(text)
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS
          pilot_runtime_receipt_is_current(text, text)
        """
    )
