pragma circom 2.0.0;

include "comparators.circom";

/*
`out` is 1 if sum of inputs signals `in` is less than signal `max`, 0 otherwise.
Each input must be at most `maxBitsInput` bits
*/
template SumLessThan(numInputs, maxBitsInput) {
    signal input in[numInputs];
    signal input max;
    signal output out;

    component validations[numInputs];

    signal intermediate[numInputs];
    
    validations[0] = Num2Bits(maxBitsInput);
    validations[0].in <== in[0];
    intermediate[0] <== in[0];

    for (var i=1; i<numInputs; i++) {
        validations[i] = Num2Bits(maxBitsInput);
        validations[i].in <== in[i];
        intermediate[i] <== intermediate[i-1] + in[i]; 
    }

    component check = LessThan(maxBitsInput + numInputs - 1);
    
    check.a <== intermediate[numInputs-1];
    check.b <== max;
    out <== check.out;
}