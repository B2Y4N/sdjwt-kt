package com.b2y4n.vc.sdjwt.utils

import java.time.Instant

/**
 * Abstraction for time provisioning, enabling deterministic time control in unit tests.
 *
 * By injecting a [TimeProvider] rather than calling [Instant.now] directly, consumers
 * such as [com.b2y4n.vc.sdjwt.presenter.SdJwtPresenter] can be tested with fixed
 * timestamps, eliminating flaky time-dependent assertions.
 */
interface TimeProvider {
    /**
     * Returns the current time as a Unix epoch timestamp in seconds.
     *
     * @return The number of seconds since 1970-01-01T00:00:00Z (UTC).
     */
    fun currentEpochSecond(): Long
}

/**
 * Default production implementation of [TimeProvider] using the system clock.
 *
 * Delegates to [Instant.now] to retrieve the current epoch second.
 */
class SystemTimeProvider : TimeProvider {
    /**
     * Returns the current system time as a Unix epoch timestamp in seconds.
     *
     * @return The number of seconds since 1970-01-01T00:00:00Z (UTC) per the system clock.
     */
    override fun currentEpochSecond(): Long = Instant.now().epochSecond
}
