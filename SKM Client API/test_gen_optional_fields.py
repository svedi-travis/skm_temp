import base64
import json
import random
from urllib.request import urlopen

OPTIONAL_FIELDS = {}
OPTIONAL_FIELDS["ID"]                 = (1, "id", "Id")
OPTIONAL_FIELDS["KEY"]                = (2, "key", "Key")
OPTIONAL_FIELDS["NOTES"]              = (3, "notes", "Notes")
OPTIONAL_FIELDS["GLOBAL_ID"]          = (4, "global_id", "GlobalId")
OPTIONAL_FIELDS["CUSTOMER"]           = (5, "customer", "Customer")
OPTIONAL_FIELDS["ACTIVATED_MACHINES"] = (6, "activated_machines", "ActivatedMachines")
OPTIONAL_FIELDS["ALLOWED_MACHINES"]   = (7, "allowed_machines", "AllowedMachines")
OPTIONAL_FIELDS["MAXNOOFMACHINES"]    = (8, "maxnoofmachines", "MaxNoOfMachines")
OPTIONAL_FIELDS["DATA_OBJECTS"]       = (9, "data_objects", "DataObjects")

def gen_features_to_return():
  features = 0
  for i in range(1, 10):
    features |= random.choice([0,1]) << i
  return features

def make_request(features):
  b64 = urlopen("https://serialkeymanager.com/api/key/Activate?token=WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0%3D&Key=HBBFA-JRULD-PGVTD-YYNDE&ProductId=3646&SignMethod=1&FieldsToReturn=" + str(features)).read().decode("utf-8")
  j = json.loads(b64)
  b64 = j["licenseKey"]
  return base64.b64decode(b64).decode("utf-8")

for field, t in OPTIONAL_FIELDS.items():
  i = t[0]
  method = t[1]
  name = t[2]

  features        = gen_features_to_return()
  with_feature    = make_request(features | 1 << i)
  without_feature = make_request(features & ~(1 << i) & ((1 << 10) - 1))

  with_feature    = with_feature.replace("\"", "\\\"")
  without_feature = without_feature.replace("\"", "\\\"")

  print("TEST(LicenseKeyOptionalFieldsGen, " + name + ") {")
  print("  std::string license1{\"" + with_feature + "\"};")
  print("  optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);")
  print()
  print("  std::string license2{\"" + without_feature + "\"};")
  print("  optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);")
  print()
  print("  ASSERT_TRUE(license_key_1.has_value()) << \"Failed to construct LicenseKey object\";")
  print("  ASSERT_TRUE(license_key_2.has_value()) << \"Failed to construct LicenseKey object\";")
  print()
  print("  EXPECT_TRUE(license_key_1->get_" + method + "().has_value());")
  print("  EXPECT_FALSE(license_key_2->get_" + method + "().has_value());")
  print("}")
  print()
