<?php

namespace GlpiPlugin\Tanium;

/**
 * Risk model shared by the endpoint risk score (0-100, higher is worse) and the
 * fleet health grade (0-10, higher is better).
 *
 * Why this class exists: the previous model summed a fixed weight per finding
 * and then clamped — `min(100, $sum)` for the risk score, `max(0.0, …)` for the
 * grade. On a real endpoint the raw sum reached ~4.400 against a ceiling of 100,
 * so the number stopped moving long before the remediation work did: closing
 * every critical AND every high CVE still displayed "100 Crítico". The scale
 * was saturated exactly where triage happens.
 *
 * The model here never saturates in practice:
 *
 *   1. The *dominant* tier (worst severity actually present) sets a floor.
 *   2. The *volume* inside that tier moves the score within the tier's band,
 *      logarithmically — the 40th critical CVE cannot cost as much as the 1st.
 *   3. The *breadth* of lower-severity findings adds a bounded amount on top.
 *
 * The consequence that matters to the user: clearing a whole severity tier
 * always drops the score into a lower band, because the floor moves down. The
 * number reacts to the work.
 *
 * Every public entry point also returns the arithmetic that produced it, so the
 * UI can show *why* an endpoint scores what it scores instead of asking people
 * to trust a bare number.
 */
class Risk {

    /**
     * Per-tier [floor, volume headroom].
     *
     * The ceilings are deliberate: base+growth+BREADTH_MAX keeps a
     * high-dominant endpoint at 69, just under the "Crítico" cut. An endpoint
     * with no critical finding can never be shown as critical, however many
     * high findings it piles up.
     */
    public const TIERS = [
        'critical' => [60.0, 30.0],  // → 60 .. 100
        'high'     => [35.0, 24.0],  // → 35 ..  69
        'medium'   => [15.0, 14.0],  // → 15 ..  39
        'low'      => [5.0,   5.0],  // →  5 ..  10
    ];

    /** Worst first — the first tier with a finding is the dominant one. */
    public const TIER_ORDER = ['critical', 'high', 'medium', 'low'];

    /** Finding count at which a tier's volume headroom is fully spent. */
    public const VOLUME_SPAN = 100;

    /** Ceiling for the lower-severity breadth term. */
    public const BREADTH_MAX = 10.0;

    /** Points a lower-severity finding decade is worth, before BREADTH_MAX. */
    public const BREADTH_RATE = 3.0;

    /** Risk bands: [min score, label key, css class]. Worst first. */
    public const BANDS = [
        [70, 'critical', 'tanium-risk-critical'],
        [40, 'high',     'tanium-risk-high'],
        [15, 'medium',   'tanium-risk-medium'],
        [0,  'low',      'tanium-risk-low'],
    ];

    /** Share of the 0-10 grade governed by findings; the rest is hygiene. */
    public const GRADE_FINDING_WEIGHT = 7.0;

    /** Hygiene deductions on the 0-10 grade — 3.0 total, mirrors the weight above. */
    public const GRADE_HYGIENE = [
        'agent_silent'  => 1.0,
        'os_eol'        => 0.8,
        'not_encrypted' => 0.6,
        'defender_bad'  => 0.6,
    ];

    /**
     * Floor applied to an endpoint whose OS no longer receives security fixes.
     *
     * An end-of-support machine with zero open findings is not a safe machine —
     * it is a machine nobody is looking for vulnerabilities in any more, and no
     * patch will ever arrive for the next one found. Landing it in the "high"
     * band states that its risk is real but not remediable by patching: the
     * fix is migration.
     */
    public const EOL_FLOOR = 40;

    /**
     * Fold raw findings into the four tiers the score is computed from.
     *
     * Two deliberate shifts happen here:
     *
     * - KEV findings are *added* to the critical tier on top of their own
     *   severity. Confirmed active exploitation is worth more than the CVSS
     *   band alone, and this reproduces the intent of the old `weight *= 2`
     *   in a way the breakdown can explain in words.
     * - Missing patches enter one tier below their severity (a critical patch
     *   lands in `high`). A patch is an exposure that has not been confirmed
     *   exploitable on this host, so it must not be able to drive an endpoint
     *   into the critical band on its own.
     *
     * @param array<string,int> $cves    keyed critical/high/medium/low
     * @param int               $kev     findings in the CISA KEV catalogue
     * @param array<string,int> $patches keyed critical/important/moderate/low
     * @return array<string,int>
     */
    public static function tierCounts(array $cves, int $kev = 0, array $patches = []): array {
        $tiers = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

        foreach (self::TIER_ORDER as $tier) {
            $tiers[$tier] += max(0, (int) ($cves[$tier] ?? 0));
        }

        $tiers['critical'] += max(0, $kev);

        $tiers['high']   += max(0, (int) ($patches['critical'] ?? 0));
        $tiers['medium'] += max(0, (int) ($patches['important'] ?? 0));
        $tiers['low']    += max(0, (int) ($patches['moderate'] ?? 0))
                          + max(0, (int) ($patches['low'] ?? 0));

        return $tiers;
    }

    /**
     * Endpoint risk score, 0-100, with the arithmetic that produced it.
     *
     * The returned `steps` are machine-readable on purpose (kind + tier +
     * count + points, no prose): the callers render their own wording, and the
     * test suite can assert on the numbers without a translation layer.
     *
     * @param array<string,int> $tiers as built by tierCounts()
     * @return array{score:int,dominant:?string,band:string,steps:array<int,array<string,mixed>>,total_findings:int}
     */
    public static function score(array $tiers): array {
        $tiers = [
            'critical' => max(0, (int) ($tiers['critical'] ?? 0)),
            'high'     => max(0, (int) ($tiers['high']     ?? 0)),
            'medium'   => max(0, (int) ($tiers['medium']   ?? 0)),
            'low'      => max(0, (int) ($tiers['low']      ?? 0)),
        ];
        $total = array_sum($tiers);

        $dominant = null;
        foreach (self::TIER_ORDER as $tier) {
            if ($tiers[$tier] > 0) {
                $dominant = $tier;
                break;
            }
        }

        if ($dominant === null) {
            return [
                'score'          => 0,
                'dominant'       => null,
                'band'           => 'low',
                'steps'          => [],
                'total_findings' => 0,
            ];
        }

        [$base, $growth] = self::TIERS[$dominant];
        $count  = $tiers[$dominant];
        $volume = $growth * self::volumeRatio($count);

        // Everything below the dominant tier. Kept bounded so a long tail of
        // low findings can never outweigh the severity that actually leads.
        $lower = 0;
        $below = false;
        foreach (self::TIER_ORDER as $tier) {
            if ($tier === $dominant) {
                $below = true;
                continue;
            }
            if ($below) {
                $lower += $tiers[$tier];
            }
        }
        $breadth = $lower > 0
            ? min(self::BREADTH_MAX, self::BREADTH_RATE * log10(1 + $lower))
            : 0.0;

        $steps = [
            ['kind' => 'base',   'tier' => $dominant, 'count' => $count, 'points' => round($base, 1)],
            ['kind' => 'volume', 'tier' => $dominant, 'count' => $count, 'points' => round($volume, 1)],
        ];
        if ($lower > 0) {
            $steps[] = ['kind' => 'breadth', 'tier' => null, 'count' => $lower, 'points' => round($breadth, 1)];
        }

        $score = (int) round(min(100.0, $base + $volume + $breadth));

        return [
            'score'          => $score,
            'dominant'       => $dominant,
            'band'           => self::band($score),
            'steps'          => $steps,
            'total_findings' => $total,
        ];
    }

    /**
     * Raise a score to EOL_FLOOR when the OS is past end of support.
     *
     * Applied after score() rather than inside it so the arithmetic stays
     * separable: the breakdown gains one explicit line saying the lift came
     * from the operating system, not from a finding, and the steps still sum
     * to the number on screen.
     *
     * @param array{score:int,band:string,steps:array<int,array<string,mixed>>} $result
     */
    public static function applyLifecycleFloor(array $result, string $state): array {
        if ($state !== 'eol' || (int) $result['score'] >= self::EOL_FLOOR) {
            return $result;
        }

        $result['steps'][] = [
            'kind'   => 'eol_floor',
            'tier'   => null,
            'count'  => 0,
            'points' => round(self::EOL_FLOOR - (int) $result['score'], 1),
        ];
        $result['score'] = self::EOL_FLOOR;
        $result['band']  = self::band(self::EOL_FLOOR);

        return $result;
    }

    /**
     * How far a tier's volume headroom is spent, 0..1.
     *
     * Logarithmic: going from 1 to 10 findings costs as much as going from 10
     * to 100. That is what keeps the score moving on an endpoint with hundreds
     * of findings instead of pinning it at the ceiling.
     */
    public static function volumeRatio(int $count): float {
        if ($count <= 0) {
            return 0.0;
        }
        return min(1.0, log10(1 + $count) / log10(1 + self::VOLUME_SPAN));
    }

    /** Band key for a 0-100 score. */
    public static function band(int $score): string {
        foreach (self::BANDS as [$min, $key, ]) {
            if ($score >= $min) {
                return $key;
            }
        }
        return 'low';
    }

    /** CSS class for a 0-100 score. */
    public static function bandClass(int $score): string {
        foreach (self::BANDS as [$min, , $class]) {
            if ($score >= $min) {
                return $class;
            }
        }
        return 'tanium-risk-low';
    }

    /**
     * Fleet health grade, 0-10 (higher is better), derived from the risk score
     * so the two numbers can never disagree about the same endpoint.
     *
     * Findings own 7 of the 10 points, hygiene the remaining 3. A 0.0 therefore
     * means "worst possible findings AND every hygiene check failing" instead
     * of the old "penalties happened to exceed 10", which dozens of endpoints
     * hit while still being very different from each other.
     *
     * @param array<string,bool> $hygiene keys of GRADE_HYGIENE that are failing
     * @return array{grade:float,steps:array<int,array<string,mixed>>}
     */
    public static function grade(int $riskScore, array $hygiene = []): array {
        $riskScore = max(0, min(100, $riskScore));
        $findingLoss = self::GRADE_FINDING_WEIGHT * ($riskScore / 100);

        $steps = [];
        if ($findingLoss > 0) {
            $steps[] = ['kind' => 'findings', 'points' => -round($findingLoss, 2), 'risk' => $riskScore];
        }

        $hygieneLoss = 0.0;
        foreach (self::GRADE_HYGIENE as $key => $cost) {
            if (!empty($hygiene[$key])) {
                $hygieneLoss += $cost;
                $steps[] = ['kind' => $key, 'points' => -$cost];
            }
        }

        $grade = round(max(0.0, 10.0 - $findingLoss - $hygieneLoss), 1);

        return ['grade' => $grade, 'steps' => $steps];
    }

    /**
     * Does this OS run Microsoft Defender at all?
     *
     * Guards the Defender hygiene check: the Tanium payload was filling
     * `defender_healthy` on Linux hosts too, and the grade was docking a point
     * from AlmaLinux/Ubuntu boxes for an agent that cannot exist there.
     */
    public static function usesDefender(?string $osName, ?string $osPlatform = null): bool {
        $haystack = strtolower(trim((string) $osName . ' ' . (string) $osPlatform));
        if ($haystack === '') {
            return false;   // unknown OS: say nothing rather than accuse
        }
        // Explicit markers only. "darwin" contains "win" — the exact trap that
        // had mapOsType() deploying Macs as Windows until the suite caught it.
        foreach (['windows', 'win32', 'win64', 'winnt', 'microsoft'] as $marker) {
            if (str_contains($haystack, $marker)) {
                return true;
            }
        }
        return false;
    }
}
