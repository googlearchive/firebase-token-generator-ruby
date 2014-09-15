require_relative "../lib/firebase_token_generator"
require "test/unit"

class TestFirebaseTokenGenerator < Test::Unit::TestCase

  def test_smoke_test
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    token = generator.create_token({:uid => "foo"})
  end

  def test_malformed_key
    assert_raise( ArgumentError ) { Firebase::FirebaseTokenGenerator.new(1234567890) }
  end

  def test_no_uid
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    assert_raise( ArgumentError ) { generator.create_token({:blah => 5}) }
  end

  def test_invalid_uid
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    assert_raise( ArgumentError ) { generator.create_token({:uid => 5, :blah => 5}) }
  end

  def test_uid_max_length
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    #length:                                         10        20        30        40        50        60        70        80        90       100       110       120       130       140       150       160       170       180       190       200       210       220       230       240       250   256
    token = generator.create_token({:uid => "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456"})
  end

  def test_uid_too_long
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    #length:                                                                10        20        30        40        50        60        70        80        90       100       110       120       130       140       150       160       170       180       190       200       210       220       230       240       250    257
    assert_raise( ArgumentError ) { generator.create_token({:uid => "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"}) }
  end

  def test_uid_min_length
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    token = generator.create_token({:uid => ""})
  end

  def test_token_too_long
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    assert_raise( RuntimeError ) { generator.create_token({:uid => "blah", :long_var => "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345612345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234561234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456"}) }
  end

  def test_no_uid_with_admin
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    token = generator.create_token(nil, {:admin => true})
    token = generator.create_token({}, {:admin => true})
    token = generator.create_token({:foo => "bar"}, {:admin => true})
  end

  def test_invalid_uid_with_admin_1
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    assert_raise( ArgumentError ) { generator.create_token({:uid => 1}, {:admin => true}) }
  end

  def test_invalid_uid_with_admin_2
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    assert_raise( ArgumentError ) { generator.create_token({:uid => nil}, {:admin => true}) }
  end

  def test_invalid_uid_with_admin_3
    generator = Firebase::FirebaseTokenGenerator.new("barfoo")
    assert_raise( ArgumentError ) { generator.create_token("foo", {:admin => true}) }
  end

end
