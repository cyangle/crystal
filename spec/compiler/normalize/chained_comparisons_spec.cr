require "../../spec_helper"

describe "Normalize: chained comparisons" do
  it "normalizes one comparison with literal" do
    assert_normalize "1 <= 2 <= 3", "if 1 <= 2\n  2 <= 3\nelse\n  false\nend"
  end

  it "normalizes one comparison with var" do
    assert_normalize "b = 1; 1 <= b <= 3", "b = 1\nif 1 <= b\n  b <= 3\nelse\n  false\nend"
  end

  it "normalizes one comparison with call" do
    assert_normalize "1 <= b <= 3", "if 1 <= (__temp_1 = b)\n  __temp_1 <= 3\nelse\n  false\nend"
  end

  it "normalizes two comparisons with literal" do
    assert_normalize "1 <= 2 <= 3 <= 4", "if 1 <= 2\n  if 2 <= 3\n    3 <= 4\n  else\n    false\n  end\nelse\n  false\nend"
  end

  it "normalizes two comparisons with calls" do
    assert_normalize "1 <= a <= b <= 4", "if 1 <= (__temp_2 = a)\n  if __temp_2 <= (__temp_1 = b)\n    __temp_1 <= 4\n  else\n    false\n  end\nelse\n  false\nend"
  end
end
