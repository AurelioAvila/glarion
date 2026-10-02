// Compare the actual yearly charge with twelve monthly payments, not an invented old price.
export function annualOffer(monthly: number, yearly: number) {
  if (!Number.isFinite(monthly) || !Number.isFinite(yearly) || monthly <= 0 || yearly <= 0 || yearly >= monthly * 12) {
    throw new RangeError("Annual offers require positive prices and a real saving.");
  }
  const standardYear = monthly * 12;
  return {
    standardYear,
    saving: standardYear - yearly,
    discount: Math.floor((standardYear - yearly) * 100 / standardYear),
    monthlyEquivalent: (yearly / 12).toFixed(2),
  };
}
