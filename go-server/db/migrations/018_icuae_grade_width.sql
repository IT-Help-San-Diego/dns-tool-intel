-- +goose Up
-- 018_icuae_grade_width.sql
-- Widen the ICuAE grade columns to fit the vocabulary the code has always
-- written.
--
-- 001_base_schema.sql sized both grade columns VARCHAR(5) DEFAULT 'F' — the
-- shape of a letter-grade vocabulary (A+ .. F, two chars, five generous).
-- But the ICuAE producer has emitted word grades since the initial commit
-- (go-server/internal/icuae/icuae.go, scoreToGrade): excellent / good /
-- adequate / degraded / stale. Three of the five exceed five characters, so
-- every scan or dimension graded excellent, adequate, or degraded failed to
-- record (SQLSTATE 22001, logged as "ICuAE: failed to record scan score")
-- while good and stale rows landed. The stored distribution was therefore a
-- systematically biased sample — the survivors were selected by string
-- length, not by anything about the scans. Measured on the dev DB
-- 2026-07-31: 16 good + 1 stale, zero rows of the other three grades.
--
-- Width 20: the longest current grade is "excellent" (9); 20 leaves room for
-- a longer future word without inviting free text. The producer vocabulary
-- is pinned under this width by TestGradeVocabularyFitsMigratedColumns,
-- which reads this file's ALTERs rather than repeating the number.
ALTER TABLE icuae_scan_scores ALTER COLUMN overall_grade TYPE VARCHAR(20);
ALTER TABLE icuae_dimension_scores ALTER COLUMN grade TYPE VARCHAR(20);

-- DEFAULT 'F' belonged to the letter vocabulary and maps to nothing in
-- GradeDisplayNames — a row created by default would carry a grade no reader
-- can display. Both insert paths (dbq ICuAEInsertScanScore /
-- ICuAEInsertDimensionScore) always bind a grade, so the default never fires
-- legitimately; dropping it makes a future grade-less insert fail loudly
-- instead of fabricating a value.
ALTER TABLE icuae_scan_scores ALTER COLUMN overall_grade DROP DEFAULT;
ALTER TABLE icuae_dimension_scores ALTER COLUMN grade DROP DEFAULT;
