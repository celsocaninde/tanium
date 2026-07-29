<?php

namespace GlpiPlugin\Tanium;

/**
 * One severity vocabulary out of many.
 *
 * The Applicable Patches sensor reports whatever the platform's own vendor
 * calls it, and the vendors do not agree. Microsoft ships Critical / Important
 * / Moderate / Low; Red Hat uses the same four words with different thresholds;
 * Ubuntu and Debian say Critical / High / Medium / Low / Negligible; SUSE
 * lower-cases its own set. A fleet running all of them stores five spellings of
 * roughly three ideas, and every count that groups by severity silently
 * fragments.
 *
 * Worse is what arrives with no severity at all. On the reference fleet that
 * was 538 rows — empty strings, the literal "none", and one "[no results]" —
 * all of which the risk model quietly folded into "low". Folding is the right
 * arithmetic (an unrated finding is not a free pass) but doing it invisibly is
 * not: nobody could tell a genuinely low-severity patch from one nobody had
 * rated. Normalising to an explicit `unknown` keeps the arithmetic and gives
 * the ambiguity a name.
 *
 * The canonical scale here is the PATCH scale (critical/important/moderate/low)
 * because that is what Risk::tierCounts() already consumes. Normalising does
 * not move any score — it only stops the same idea being spelled five ways.
 */
class Severity {

    /** Canonical patch severities, worst first. */
    public const PATCH_SCALE = ['critical', 'important', 'moderate', 'low', 'unknown'];

    /**
     * Vendor spelling → canonical patch severity.
     *
     * Deliberately explicit rather than clever: a lookup table is auditable,
     * and a word nobody mapped becomes `unknown` instead of being guessed into
     * a bucket that changes someone's risk score.
     */
    private const PATCH_MAP = [
        // Microsoft / Red Hat / Oracle / SUSE share these four words.
        'critical'    => 'critical',
        'important'   => 'important',
        'moderate'    => 'moderate',
        'low'         => 'low',
        // Ubuntu / Debian / CVSS-style wording.
        'high'        => 'important',
        'medium'      => 'moderate',
        'negligible'  => 'low',
        'untriaged'   => 'unknown',
        // Microsoft's own "no rating" values.
        'unspecified' => 'unknown',
        'none'        => 'unknown',
        'n/a'         => 'unknown',
        'unknown'     => 'unknown',
    ];

    /** CVE severities use the CVSS words; patches use the vendor words. */
    private const CVE_MAP = [
        'critical'   => 'critical',
        'high'       => 'high',
        'important'  => 'high',
        'medium'     => 'medium',
        'moderate'   => 'medium',
        'low'        => 'low',
        'negligible' => 'low',
        'none'       => 'unknown',
        'n/a'        => 'unknown',
        'unknown'    => 'unknown',
    ];

    /**
     * Normalise a patch severity as reported by any platform.
     *
     * Anything unrecognised — including the sensor's own error artefacts — is
     * `unknown`, never a guess.
     */
    public static function patch(?string $raw): string {
        $key = strtolower(trim((string) $raw));
        if ($key === '' || $key === '[no results]') {
            return 'unknown';
        }
        return self::PATCH_MAP[$key] ?? 'unknown';
    }

    /** Normalise a CVE severity onto the CVSS scale. */
    public static function cve(?string $raw): string {
        $key = strtolower(trim((string) $raw));
        if ($key === '' || $key === '[no results]') {
            return 'unknown';
        }
        return self::CVE_MAP[$key] ?? 'unknown';
    }

    /**
     * True when the value carries no usable rating.
     *
     * Callers use this to surface the gap rather than to change any score —
     * see the data-quality check in Diagnostics.
     */
    public static function isUnrated(?string $raw): bool {
        return self::patch($raw) === 'unknown';
    }
}
