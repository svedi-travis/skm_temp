#include <iostream>

#include "gtest/gtest.h"

#include "basic_SKM.hpp"
#include "LicenseKey.hpp"
#include "LicenseKeyChecker.hpp"
#include "RawLicenseKey.hpp"

#include "RequestHandler_static.hpp"
#include "SignatureVerifier_OpenSSL.hpp"

using namespace serialkeymanager_com;

using SKM = basic_SKM<RequestHandler_static,SignatureVerifier_OpenSSL>;

struct LicenseKeyExpected
{
  std::string license;
  bool f1;
  bool f2;
  bool f3;
  bool f4;
  bool f5;
  bool f6;
  bool f7;
  bool f8;

  void check() const
  {
    optional<LicenseKey> license_key = LicenseKey::make_unsafe(license);

    ASSERT_TRUE(license_key.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_EQ(license_key->get_f1(), f1);
    EXPECT_EQ(license_key->get_f2(), f2);
    EXPECT_EQ(license_key->get_f3(), f3);
    EXPECT_EQ(license_key->get_f4(), f4);
    EXPECT_EQ(license_key->get_f5(), f5);
    EXPECT_EQ(license_key->get_f6(), f6);
    EXPECT_EQ(license_key->get_f7(), f7);
    EXPECT_EQ(license_key->get_f8(), f8);

    EXPECT_EQ((bool)license_key->check().has_feature(1), f1);
    EXPECT_EQ((bool)license_key->check().has_feature(2), f2);
    EXPECT_EQ((bool)license_key->check().has_feature(3), f3);
    EXPECT_EQ((bool)license_key->check().has_feature(4), f4);
    EXPECT_EQ((bool)license_key->check().has_feature(5), f5);
    EXPECT_EQ((bool)license_key->check().has_feature(6), f6);
    EXPECT_EQ((bool)license_key->check().has_feature(7), f7);
    EXPECT_EQ((bool)license_key->check().has_feature(8), f8);

    EXPECT_EQ((bool)license_key->check().has_not_feature(1), !f1);
    EXPECT_EQ((bool)license_key->check().has_not_feature(2), !f2);
    EXPECT_EQ((bool)license_key->check().has_not_feature(3), !f3);
    EXPECT_EQ((bool)license_key->check().has_not_feature(4), !f4);
    EXPECT_EQ((bool)license_key->check().has_not_feature(5), !f5);
    EXPECT_EQ((bool)license_key->check().has_not_feature(6), !f6);
    EXPECT_EQ((bool)license_key->check().has_not_feature(7), !f7);
    EXPECT_EQ((bool)license_key->check().has_not_feature(8), !f8);
  }
};

TEST(LicenseKeyAttributes, Mandatory) {
  std::string license{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key = LicenseKey::make_unsafe(license);

    ASSERT_TRUE(license_key.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_EQ(license_key->get_product_id(), 3646);
    EXPECT_EQ(license_key->get_created(), 1490313600);
    EXPECT_EQ(license_key->get_expires(), 1492905600);
    EXPECT_EQ(license_key->get_period(), 30);
    EXPECT_EQ(license_key->get_block(), false);
    EXPECT_EQ(license_key->get_trial_activation(), false);
    EXPECT_EQ(license_key->get_sign_date(), 1495226191);
    EXPECT_EQ(license_key->get_expires(), 1492905600);
}

TEST(LicenseKeyChecker, Mandatory) {
  std::string license{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key = LicenseKey::make_unsafe(license);

    ASSERT_TRUE(license_key.has_value()) << "Failed to construct LicenseKey object";

    
    EXPECT_EQ((bool)license_key->check().has_expired(1492905650), true);
    EXPECT_EQ((bool)license_key->check().has_expired(1492905550), false);

    EXPECT_EQ((bool)license_key->check().has_not_expired(1492905650), false);
    EXPECT_EQ((bool)license_key->check().has_not_expired(1492905550), true);

    EXPECT_EQ((bool)license_key->check().has_expired(1492905650).has_not_expired(1492905550), true);
    EXPECT_EQ((bool)license_key->check().has_expired(1492905550).has_not_expired(1492905550), false);
    EXPECT_EQ((bool)license_key->check().has_expired(1492905650).has_not_expired(1492905650), false);
    EXPECT_EQ((bool)license_key->check().has_expired(1492905550).has_not_expired(1492905650), false);

    EXPECT_EQ( (bool)license_key->check().has_not_feature(1).has_not_feature(2)
		                         .has_not_feature(3).has_not_feature(4)
		                         .has_not_feature(5).has_not_feature(6)
		                         .has_not_feature(7).has_feature(8)
             , true);
    EXPECT_EQ( (bool)license_key->check().has_not_feature(1).has_not_feature(2)
		                         .has_not_feature(3).has_not_feature(4)
		                         .has_not_feature(5).has_not_feature(6)
		                         .has_not_feature(7).has_not_feature(8)
             , false);
    EXPECT_EQ( (bool)license_key->check().has_feature(1).has_not_feature(2)
		                         .has_not_feature(3).has_feature(4)
		                         .has_feature(5).has_not_feature(6)
		                         .has_not_feature(7).has_not_feature(8)
             , false);
}

TEST(LicenseKeyOptional, Id) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_id().has_value());
    EXPECT_FALSE(license_key_2->get_id().has_value());
}

TEST(LicenseKeyOptional, Key) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":null,\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_key().has_value());
    EXPECT_FALSE(license_key_2->get_key().has_value());
}

TEST(LicenseKeyOptional, Notes) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":\"my little note\",\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":null,\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_notes().has_value());
    EXPECT_FALSE(license_key_2->get_notes().has_value());
}

TEST(LicenseKeyOptional, GlobalId) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":\"my little note\",\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":null,\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":null,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_global_id().has_value());
    EXPECT_FALSE(license_key_2->get_global_id().has_value());
}

TEST(LicenseKeyOptional, MaxNoOfMachines) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":\"my little note\",\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":null,\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":null,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":null,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_maxnoofmachines().has_value());
    EXPECT_FALSE(license_key_2->get_maxnoofmachines().has_value());
}

TEST(LicenseKeyOptional, AllowedMachines) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":\"my little note\",\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":null,\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":null,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":null,\"AllowedMachines\":null,\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_allowed_machines().has_value());
    EXPECT_FALSE(license_key_2->get_allowed_machines().has_value());
}

TEST(LicenseKeyOptional, DataObjects) {
  std::string license1{"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":\"my little note\",\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_1 = LicenseKey::make_unsafe(license1);

  std::string license2{"{\"ProductId\":3646,\"ID\":null,\"Key\":null,\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":null,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":null,\"AllowedMachines\":null,\"DataObjects\":null,\"SignDate\":1495226191}"};
    optional<LicenseKey> license_key_2 = LicenseKey::make_unsafe(license2);


    ASSERT_TRUE(license_key_1.has_value()) << "Failed to construct LicenseKey object";
    ASSERT_TRUE(license_key_2.has_value()) << "Failed to construct LicenseKey object";

    EXPECT_TRUE(license_key_1->get_data_objects().has_value());
    EXPECT_FALSE(license_key_2->get_data_objects().has_value());
}

TEST(LicenseKeyFeatures, None) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = true;

  expect.check();
}

TEST(LicenseKeyFeatures, F1) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":true,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = true;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F2) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":true,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = true;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F3) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":true,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = true;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F4) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":true,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = true;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F5) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":true,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = true;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F6) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":true,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = true;
  expect.f7 = false;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F7) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":true,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = true;
  expect.f8 = false;

  expect.check();
}

TEST(LicenseKeyFeatures, F8) {
  LicenseKeyExpected expect;
  expect.license = "{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":true,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":1,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495226191}";
  expect.f1 = false;
  expect.f2 = false;
  expect.f3 = false;
  expect.f4 = false;
  expect.f5 = false;
  expect.f6 = false;
  expect.f7 = false;
  expect.f8 = true;

  expect.check();
}

TEST(basic_SKM_activate, Normal) {
  SKM skm;
  skm.signature_verifier.set_modulus_base64("khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==");
  skm.signature_verifier.set_exponent_base64("AQAB");
  skm.request_handler.set_response("{\"licenseKey\":\"eyJQcm9kdWN0SWQiOjM2NDYsIklEIjo0LCJLZXkiOiJNUERXWS1QUUFPVy1GS1NDSC1TR0FBVSIsIkNyZWF0ZWQiOjE0OTAzMTM2MDAsIkV4cGlyZXMiOjE0OTI5MDU2MDAsIlBlcmlvZCI6MzAsIkYxIjpmYWxzZSwiRjIiOmZhbHNlLCJGMyI6ZmFsc2UsIkY0IjpmYWxzZSwiRjUiOmZhbHNlLCJGNiI6ZmFsc2UsIkY3IjpmYWxzZSwiRjgiOmZhbHNlLCJOb3RlcyI6bnVsbCwiQmxvY2siOmZhbHNlLCJHbG9iYWxJZCI6MzE4NzYsIkN1c3RvbWVyIjpudWxsLCJBY3RpdmF0ZWRNYWNoaW5lcyI6W3siTWlkIjoiIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxODk4OTE4fSx7Ik1pZCI6ImxvbCIsIklQIjoiMTU1LjQuMTM0LjI3IiwiVGltZSI6MTQ5MTg5ODk5NX0seyJNaWQiOiIyODlqZjJhZnNmIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxOTAwNTQ2fSx7Ik1pZCI6IjI4OWpmMmFmczMiLCJJUCI6IjE1NS40LjEzNC4yNyIsIlRpbWUiOjE0OTE5MDA2MzZ9XSwiVHJpYWxBY3RpdmF0aW9uIjpmYWxzZSwiTWF4Tm9PZk1hY2hpbmVzIjoxMCwiQWxsb3dlZE1hY2hpbmVzIjoiIiwiRGF0YU9iamVjdHMiOltdLCJTaWduRGF0ZSI6MTQ5NTAxOTc2Nn0=\",\"signature\":\"SqPm8dtTdVBrXrmJzXer7qq6dvdQfctJxP8mar+RO9p8QABsgWWaX+uH7aOGMBd42eg+2Omorv7Ks6V7itRhXPeeq5qWoKuefd+pTsFagvqiu2N/E2Np8fpt51aqmiygdHLECo42nJwVD8JzlN67hnvJTgY7iyDWhG7qFK9Slk+kEJjjK/0J1pJYI6nOi+7sgBV7ZRca+7DmiP6OmOjNfySps6PdiB7QbiSis5f24Xmc5OYyRe3fzZmAueqF3eymBK19XhYFroWXeT4tcNsBNJsv+YfItovGbJysLx+K4ppltd2GNwEFQgtE3ILGOUj7EVbeQmQXg9m2c5MTPyk8iA==\",\"result\":0,\"message\":\"\"}");

  auto raw_license_key = 
    skm.activate( "dummy access token"
                , "dummy product id"
                , "dummy license key"
                , "dummy machine");

  ASSERT_TRUE(raw_license_key.has_value());

  EXPECT_EQ(raw_license_key->get_license(),"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":10,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495019766}"); 
}

TEST(basic_SKM_activate, NoPublicKey) {
  SKM skm;
  skm.request_handler.set_response("{\"licenseKey\":\"eyJQcm9kdWN0SWQiOjM2NDYsIklEIjo0LCJLZXkiOiJNUERXWS1QUUFPVy1GS1NDSC1TR0FBVSIsIkNyZWF0ZWQiOjE0OTAzMTM2MDAsIkV4cGlyZXMiOjE0OTI5MDU2MDAsIlBlcmlvZCI6MzAsIkYxIjpmYWxzZSwiRjIiOmZhbHNlLCJGMyI6ZmFsc2UsIkY0IjpmYWxzZSwiRjUiOmZhbHNlLCJGNiI6ZmFsc2UsIkY3IjpmYWxzZSwiRjgiOmZhbHNlLCJOb3RlcyI6bnVsbCwiQmxvY2siOmZhbHNlLCJHbG9iYWxJZCI6MzE4NzYsIkN1c3RvbWVyIjpudWxsLCJBY3RpdmF0ZWRNYWNoaW5lcyI6W3siTWlkIjoiIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxODk4OTE4fSx7Ik1pZCI6ImxvbCIsIklQIjoiMTU1LjQuMTM0LjI3IiwiVGltZSI6MTQ5MTg5ODk5NX0seyJNaWQiOiIyODlqZjJhZnNmIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxOTAwNTQ2fSx7Ik1pZCI6IjI4OWpmMmFmczMiLCJJUCI6IjE1NS40LjEzNC4yNyIsIlRpbWUiOjE0OTE5MDA2MzZ9XSwiVHJpYWxBY3RpdmF0aW9uIjpmYWxzZSwiTWF4Tm9PZk1hY2hpbmVzIjoxMCwiQWxsb3dlZE1hY2hpbmVzIjoiIiwiRGF0YU9iamVjdHMiOltdLCJTaWduRGF0ZSI6MTQ5NTAxOTc2Nn0=\",\"signature\":\"SqPm8dtTdVBrXrmJzXer7qq6dvdQfctJxP8mar+RO9p8QABsgWWaX+uH7aOGMBd42eg+2Omorv7Ks6V7itRhXPeeq5qWoKuefd+pTsFagvqiu2N/E2Np8fpt51aqmiygdHLECo42nJwVD8JzlN67hnvJTgY7iyDWhG7qFK9Slk+kEJjjK/0J1pJYI6nOi+7sgBV7ZRca+7DmiP6OmOjNfySps6PdiB7QbiSis5f24Xmc5OYyRe3fzZmAueqF3eymBK19XhYFroWXeT4tcNsBNJsv+YfItovGbJysLx+K4ppltd2GNwEFQgtE3ILGOUj7EVbeQmQXg9m2c5MTPyk8iA==\",\"result\":0,\"message\":\"\"}");

  auto raw_license_key = 
    skm.activate( "dummy access token"
                , "dummy product id"
                , "dummy license key"
                , "dummy machine");

  EXPECT_FALSE(raw_license_key.has_value());
}

TEST(basic_SKM_activate_exn, Normal) {
  SKM skm;
  skm.signature_verifier.set_modulus_base64("khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==");
  skm.signature_verifier.set_exponent_base64("AQAB");
  skm.request_handler.set_response("{\"licenseKey\":\"eyJQcm9kdWN0SWQiOjM2NDYsIklEIjo0LCJLZXkiOiJNUERXWS1QUUFPVy1GS1NDSC1TR0FBVSIsIkNyZWF0ZWQiOjE0OTAzMTM2MDAsIkV4cGlyZXMiOjE0OTI5MDU2MDAsIlBlcmlvZCI6MzAsIkYxIjpmYWxzZSwiRjIiOmZhbHNlLCJGMyI6ZmFsc2UsIkY0IjpmYWxzZSwiRjUiOmZhbHNlLCJGNiI6ZmFsc2UsIkY3IjpmYWxzZSwiRjgiOmZhbHNlLCJOb3RlcyI6bnVsbCwiQmxvY2siOmZhbHNlLCJHbG9iYWxJZCI6MzE4NzYsIkN1c3RvbWVyIjpudWxsLCJBY3RpdmF0ZWRNYWNoaW5lcyI6W3siTWlkIjoiIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxODk4OTE4fSx7Ik1pZCI6ImxvbCIsIklQIjoiMTU1LjQuMTM0LjI3IiwiVGltZSI6MTQ5MTg5ODk5NX0seyJNaWQiOiIyODlqZjJhZnNmIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxOTAwNTQ2fSx7Ik1pZCI6IjI4OWpmMmFmczMiLCJJUCI6IjE1NS40LjEzNC4yNyIsIlRpbWUiOjE0OTE5MDA2MzZ9XSwiVHJpYWxBY3RpdmF0aW9uIjpmYWxzZSwiTWF4Tm9PZk1hY2hpbmVzIjoxMCwiQWxsb3dlZE1hY2hpbmVzIjoiIiwiRGF0YU9iamVjdHMiOltdLCJTaWduRGF0ZSI6MTQ5NTAxOTc2Nn0=\",\"signature\":\"SqPm8dtTdVBrXrmJzXer7qq6dvdQfctJxP8mar+RO9p8QABsgWWaX+uH7aOGMBd42eg+2Omorv7Ks6V7itRhXPeeq5qWoKuefd+pTsFagvqiu2N/E2Np8fpt51aqmiygdHLECo42nJwVD8JzlN67hnvJTgY7iyDWhG7qFK9Slk+kEJjjK/0J1pJYI6nOi+7sgBV7ZRca+7DmiP6OmOjNfySps6PdiB7QbiSis5f24Xmc5OYyRe3fzZmAueqF3eymBK19XhYFroWXeT4tcNsBNJsv+YfItovGbJysLx+K4ppltd2GNwEFQgtE3ILGOUj7EVbeQmQXg9m2c5MTPyk8iA==\",\"result\":0,\"message\":\"\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");

    EXPECT_EQ(raw_license_key.get_license(),"{\"ProductId\":3646,\"ID\":4,\"Key\":\"MPDWY-PQAOW-FKSCH-SGAAU\",\"Created\":1490313600,\"Expires\":1492905600,\"Period\":30,\"F1\":false,\"F2\":false,\"F3\":false,\"F4\":false,\"F5\":false,\"F6\":false,\"F7\":false,\"F8\":false,\"Notes\":null,\"Block\":false,\"GlobalId\":31876,\"Customer\":null,\"ActivatedMachines\":[{\"Mid\":\"\",\"IP\":\"155.4.134.27\",\"Time\":1491898918},{\"Mid\":\"lol\",\"IP\":\"155.4.134.27\",\"Time\":1491898995},{\"Mid\":\"289jf2afsf\",\"IP\":\"155.4.134.27\",\"Time\":1491900546},{\"Mid\":\"289jf2afs3\",\"IP\":\"155.4.134.27\",\"Time\":1491900636}],\"TrialActivation\":false,\"MaxNoOfMachines\":10,\"AllowedMachines\":\"\",\"DataObjects\":[],\"SignDate\":1495019766}"); 
  } catch (ActivateError const& e) {
    ASSERT_TRUE(false) << "Unexpected exception \"" << e.what()
                       << "\" with code " << e.get_reason() << std::endl;
  }
}

TEST(basic_SKM_activate_exn, NoPublicKey) {
  SKM skm;
  skm.request_handler.set_response("{\"licenseKey\":\"eyJQcm9kdWN0SWQiOjM2NDYsIklEIjo0LCJLZXkiOiJNUERXWS1QUUFPVy1GS1NDSC1TR0FBVSIsIkNyZWF0ZWQiOjE0OTAzMTM2MDAsIkV4cGlyZXMiOjE0OTI5MDU2MDAsIlBlcmlvZCI6MzAsIkYxIjpmYWxzZSwiRjIiOmZhbHNlLCJGMyI6ZmFsc2UsIkY0IjpmYWxzZSwiRjUiOmZhbHNlLCJGNiI6ZmFsc2UsIkY3IjpmYWxzZSwiRjgiOmZhbHNlLCJOb3RlcyI6bnVsbCwiQmxvY2siOmZhbHNlLCJHbG9iYWxJZCI6MzE4NzYsIkN1c3RvbWVyIjpudWxsLCJBY3RpdmF0ZWRNYWNoaW5lcyI6W3siTWlkIjoiIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxODk4OTE4fSx7Ik1pZCI6ImxvbCIsIklQIjoiMTU1LjQuMTM0LjI3IiwiVGltZSI6MTQ5MTg5ODk5NX0seyJNaWQiOiIyODlqZjJhZnNmIiwiSVAiOiIxNTUuNC4xMzQuMjciLCJUaW1lIjoxNDkxOTAwNTQ2fSx7Ik1pZCI6IjI4OWpmMmFmczMiLCJJUCI6IjE1NS40LjEzNC4yNyIsIlRpbWUiOjE0OTE5MDA2MzZ9XSwiVHJpYWxBY3RpdmF0aW9uIjpmYWxzZSwiTWF4Tm9PZk1hY2hpbmVzIjoxMCwiQWxsb3dlZE1hY2hpbmVzIjoiIiwiRGF0YU9iamVjdHMiOltdLCJTaWduRGF0ZSI6MTQ5NTAxOTc2Nn0=\",\"signature\":\"SqPm8dtTdVBrXrmJzXer7qq6dvdQfctJxP8mar+RO9p8QABsgWWaX+uH7aOGMBd42eg+2Omorv7Ks6V7itRhXPeeq5qWoKuefd+pTsFagvqiu2N/E2Np8fpt51aqmiygdHLECo42nJwVD8JzlN67hnvJTgY7iyDWhG7qFK9Slk+kEJjjK/0J1pJYI6nOi+7sgBV7ZRca+7DmiP6OmOjNfySps6PdiB7QbiSis5f24Xmc5OYyRe3fzZmAueqF3eymBK19XhYFroWXeT4tcNsBNJsv+YfItovGbJysLx+K4ppltd2GNwEFQgtE3ILGOUj7EVbeQmQXg9m2c5MTPyk8iA==\",\"result\":0,\"message\":\"\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::SIGNATURE_CHECK_FAILED) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, NonsenseResponse) {
  SKM skm;
  skm.request_handler.set_response("asdfasdf");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::JSON_PARSE_FAILED) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, NonsenseJson) {
  SKM skm;
  skm.request_handler.set_response("{\"asdfasdf\": \"qwerqwer\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::UNKNOWN_SERVER_REPLY) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, InvalidAccessToken) {
  SKM skm;
  skm.request_handler.set_response("{\"result\":1,\"message\":\"Unable to authenticate.\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::INVALID_ACCESS_TOKEN) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, AccessDenied) {
  SKM skm;
  skm.request_handler.set_response("{\"result\":1,\"message\":\"Access denied.\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::ACCESS_DENIED) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, ProductNotFound) {
  SKM skm;
  skm.request_handler.set_response("{\"result\":1,\"message\":\"Could not find the product.\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::PRODUCT_NOT_FOUND) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, KeyNotFound) {
  SKM skm;
  skm.request_handler.set_response("{\"result\":1,\"message\":\"Could not find the key.\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::KEY_NOT_FOUND) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, KeyIsBlocked) {
  SKM skm;
  skm.request_handler.set_response("{\"result\":1,\"message\":\"The key is blocked and cannot be accessed.\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::KEY_BLOCKED) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

TEST(basic_SKM_activate_exn, DeviceLimitReached) {
  SKM skm;
  skm.request_handler.set_response("{\"result\":1,\"message\":\"Cannot activate the new device as the limit has been reached.\"}");

  try {
    auto raw_license_key = 
      skm.activate_exn( experimental_v1()
                      , "dummy access token"
                      , "dummy product id"
                      , "dummy license key"
                      , "dummy machine");
  } catch (ActivateError const& e) {
    if (e.get_reason() != ActivateError::DEVICE_LIMIT_REACHED) {
      ASSERT_TRUE(false) << "Unexpected exception: \"" << e.what()
                         << "\" with code " << e.get_reason() << std::endl;
    }
    return;
  }

  ASSERT_TRUE(false) << "Did not get expected exception";
}

int
main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
