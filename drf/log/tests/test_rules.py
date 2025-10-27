from django.contrib.auth import get_user_model
from django.test import TestCase

from qux.drf.log.models import APILoggingRule
from qux.drf.log.rules import should_log


class TestLoggingRules(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user(
            username="u1", email="u1@example.com"
        )
        self.user.set_unusable_password()
        self.user.save()

    def test_allow_rule_enables_logging(self):
        APILoggingRule.objects.create(user=self.user, is_allow=True, active=True)
        self.assertTrue(should_log(f"userid_{self.user.id}"))

    def test_deny_overrides_allow(self):
        APILoggingRule.objects.create(user=self.user, is_allow=True, active=True)
        # Add deny by deactivating allow and creating deny
        APILoggingRule.objects.all().update(active=False)
        APILoggingRule.objects.create(user=self.user, is_allow=False, active=True)
        self.assertFalse(should_log(f"userid_{self.user.id}"))

    def test_unknown_user_defaults_allow(self):
        self.assertTrue(should_log("userid_99999"))
