import pytest
@pytest.mark.skip
@pytest.mark.great
def test_greater():
   num = 100
   assert num > 100

@pytest.mark.great_equal
def test_greater_equal():
   num = 100
   assert num >= 100

def test_less():
   num = 100
   assert num < 200
