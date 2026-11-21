# Terms of the HealthLog push relay

Version 1.0, 2026-11-21 (terms version `2026-11-21`). Served at https://push.healthlog.dev/terms.

These terms apply to the hosted relay at push.healthlog.dev. The operator of a HealthLog server accepts them
when switching the relay on for that server.

1. Free of charge. The relay costs nothing. There is no contract for a paid service and no support
   obligation.

2. Best effort. The relay is run with care, but without any guarantee. The target is 99.5 % availability
   over 30 days. That is a target, not a promise.

3. Household use only. The relay is for a HealthLog server that a person runs privately for themselves or
   their family. Organisations (for example practices, care services, professional guardians or clubs) use
   their own APNs key, run their own relay, or ask at relay@healthlog.dev.

4. Only for HealthLog. The relay serves HealthLog servers and the HealthLog app from the App Store, and
   nothing else.

5. Not a medical service. The relay is not a medical device and not a replacement for reminders on the
   device. Notifications can be late, arrive twice or not at all. Reminders that the app schedules on the
   device stay authoritative. Clearing a notification on your other devices is a convenience and can fail.

6. Limits apply. Every server and every device is subject to the limits published in the README of
   https://github.com/MBombeck/healthlog-push. A refusal names the limit and when to try again.

7. Suspension. A server that abuses the relay, sends to devices that did not agree, or breaks these terms
   can be throttled, suspended or revoked. A suspended server receives the reason from a fixed list with
   every refused request. You can appeal by writing to abuse@healthlog.dev with your instance id.

8. One person operates it. The relay is run by one person, the maintainer of the HealthLog project. Replies
   to appeals and reports can take time, and a suspension may stay in place for up to 14 days before it is
   reviewed.

9. Shutdown. If the hosted relay is shut down, this is announced at least 90 days in advance through the
   relay's notice to all servers. Afterwards all data is deleted.

10. Privacy. What the relay sees and stores is described at https://push.healthlog.dev/privacy.

Contact: relay@healthlog.dev (operation), abuse@healthlog.dev (abuse and appeals), privacy@healthlog.dev
(data protection).
