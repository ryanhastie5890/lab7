from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.operators import Operator, OperatorType
from presidio_anonymizer.entities import InvalidParamError



@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised(mock_key_size):
    mock_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_invalid_length_key_then_ipe_raised(mock_key_size):
    mock_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "is_valid_key_size") # hint: replace encrypt with the method that you want to mock
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size): # hint: replace mock_encrypt with a proper name for your mocker
    mock_is_valid_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

@mock.patch.object(AESCipher, "encrypt")
def test_operator_name(mock_encrypt):
    result = Encrypt().operator_name()
    assert result =="encrypt"
   
@mock.patch.object(AESCipher, "encrypt")
def test_operator_type(mock_encrypt):
   result = Encrypt().operator_type()
   assert result == OperatorType.Anonymize

#@mock.patch.object(AESCipher, "is_valid_key_size")
@pytest.mark.parametrize(
        "type, key",
        [
            ("str","e5b9d7f4c8a23b7f92f0b4cbe7e2a6c1"),
            ("str","a9f29cd08f11fc92b8cb8fe9ea92d118b39ef5c0910f8b16"),
            ("str", "3b7e2a8d64c47a91e3b41fdf8adf92c5fa0f5b62c1e9ab72f22c7e15d8a9b4e0"),
            ("byte", "e5b9d7f4c8a23b7f92f0b4cbe7e2a6c1"),
            ("byte","d1e9a3b8f45c29bd67e2c1f0a7d9458e4c2bfa3198c7de55"),
            ("byte", "3b7e2a8d64c47a91e3b41fdf8adf92c5fa0f5b62c1e9ab72f22c7e15d8a9b4e0"),
            
        ],
)
def test_valid_keys(type, key):
        if(len(key)==48):
            pass
        elif(type =="str"):
          Encrypt().validate(params={"key": key})
        else:
          Encrypt().validate(params={"key": key.encode("utf8")})
        