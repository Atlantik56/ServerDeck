import pathlib,tempfile,unittest
from control import MutationBusy

class MaintenanceFreeze(unittest.TestCase):
 def test_membership_respects_file_across_instances_without_destroying_reservations(self):
  with tempfile.TemporaryDirectory() as tmp:
   marker=pathlib.Path(tmp)/'deployment-freeze';busy=MutationBusy(marker);busy.add('existing-job')
   self.assertIn('existing-job',busy);self.assertNotIn('new-host',busy)
   marker.touch();self.assertIn('any-new-host',busy);self.assertTrue(busy)
   fresh=MutationBusy(marker);self.assertIn('bot-target',fresh);self.assertTrue(fresh)
   busy.discard('unrelated-host');self.assertIn('new-host',busy)
   marker.unlink();self.assertIn('existing-job',busy);self.assertNotIn('new-host',busy);self.assertFalse(fresh)
 def test_existing_completion_cannot_release_global_freeze(self):
  with tempfile.TemporaryDirectory() as tmp:
   marker=pathlib.Path(tmp)/'deployment-freeze';marker.touch();busy=MutationBusy(marker);busy.add('host');busy.discard('host')
   self.assertTrue(busy);self.assertIn('host',busy);self.assertTrue(marker.exists())

if __name__=='__main__':unittest.main()
