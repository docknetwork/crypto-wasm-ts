import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  EncodeFunc,
  Encoder,
  flattenObjectToKeyValuesList,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1
} from '../../../src';
import { stringToBytes } from '../../utils';

describe('Utils', () => {
  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  it('flattening works', () => {
    const msgs1 = { foo: 'Foo1', 'bar-0': 'Bar0', bar: 'Bar', grault: 'aGrault', corge: 'Corge', waldo: 'Waldo' };
    const [keys1, vals1] = flattenObjectToKeyValuesList(msgs1);
    expect(keys1.length).toEqual(vals1.length);
    expect(keys1).toEqual(['bar', 'bar-0', 'corge', 'foo', 'grault', 'waldo']);
    expect(vals1).toEqual(['Bar', 'Bar0', 'Corge', 'Foo1', 'aGrault', 'Waldo']);

    const msgs2 = { foo: 'Foo1', bar: 'Bar1', baz: { foo0: 'Foo10', bar: 'Bar4' } };
    const [keys2, vals2] = flattenObjectToKeyValuesList(msgs2);
    expect(keys2.length).toEqual(vals2.length);
    expect(keys2).toEqual(['bar', 'baz.bar', 'baz.foo0', 'foo']);
    expect(vals2).toEqual(['Bar1', 'Bar4', 'Foo10', 'Foo1']);

    const msgs3 = { foo: 'Foo1', bar: 'Bar10', baz: { foo0: 'Foo', bar: 'Bar4' }, axe: ['foo', 'bar', 1] };
    const [keys3, vals3] = flattenObjectToKeyValuesList(msgs3);
    expect(keys3.length).toEqual(vals3.length);
    expect(keys3).toEqual(['axe.0', 'axe.1', 'axe.2', 'bar', 'baz.bar', 'baz.foo0', 'foo']);
    expect(vals3).toEqual(['foo', 'bar', 1, 'Bar10', 'Bar4', 'Foo', 'Foo1']);
  });

  it('Signature params getter', () => {
    const params1 = BBSPlusSignatureParamsG1.generate(2);

    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(1, params1)).toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(3, params1)).toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(2, params1)).not.toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(1, stringToBytes('some label'))).not.toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(2, stringToBytes('some label'))).not.toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(3, stringToBytes('some label'))).not.toThrow();

    const params2 = BBSPlusSignatureParamsG1.generate(2, stringToBytes('label2'));
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(1, params2)).not.toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(2, params2)).not.toThrow();
    expect(() => BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(3, params2)).not.toThrow();
  });

  it('encoder works', () => {
    expect(() => new Encoder()).toThrow();
    expect(() => new Encoder(new Map<string, EncodeFunc>())).toThrow();

    const encoders1 = new Map<string, EncodeFunc>();
    encoders1.set('foo', Encoder.positiveIntegerEncoder());
    const encoder1 = new Encoder(encoders1);

    // Throws for undefined message
    expect(() => encoder1.encodeMessage('bar', undefined)).toThrow();

    // Throws for unknown message name when no default encoder
    expect(() => encoder1.encodeMessage('bar', 6)).toThrow();
    expect(() => encoder1.encodeMessageObject({ bar: 6, foo: 10 })).toThrow();

    // Throws for known message name but invalid value
    expect(() => encoder1.encodeMessage('foo', 6.5)).toThrow();
    expect(() => encoder1.encodeMessageObject({ foo: 6.5 })).toThrow();

    expect(() => encoder1.encodeMessage('foo', 6)).not.toThrow();
    expect(() => encoder1.encodeMessageObject({ foo: 6 })).not.toThrow();

    const defaultEncoder = (v: unknown) => {
      // @ts-ignore
      return BBSPlusSignatureG1.encodeMessageForSigning(stringToBytes(v.toString()));
    };
    const encoder2 = new Encoder(undefined, defaultEncoder);
    expect(() => encoder2.encodeMessage('bar', 6)).not.toThrow();
    expect(() => encoder2.encodeMessageObject({ bar: 6 })).not.toThrow();

    const encoder3 = new Encoder(encoders1, defaultEncoder);
    // Throws for known message name but invalid value even with default encoder
    expect(() => encoder3.encodeMessage('foo', 6.5)).toThrow();
    expect(() => encoder3.encodeMessageObject({ bar: 10, foo: 6.5 })).toThrow();

    // Throws when integer encoder is given a decimal number as minimum
    expect(() => Encoder.integerEncoder(-100.2)).toThrow();
    expect(() => Encoder.integerEncoder(100.2)).toThrow();

    // Does not throw when given a positive integer
    expect(() => Encoder.integerEncoder(100)).not.toThrow();

    encoders1.set('bar', Encoder.integerEncoder(-100));

    const encoder4 = new Encoder(encoders1, defaultEncoder);

    // Throws when message is not an integer
    expect(() => encoder4.encodeMessage('bar', 2.6)).toThrow();
    expect(() => encoder4.encodeMessage('bar', -2.6)).toThrow();
    expect(() => encoder4.encodeMessage('bar', 'Bar1')).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: 2.6 })).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: -2.6 })).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: 'Bar1' })).toThrow();

    // Does not throw when positive integers
    expect(() => encoder4.encodeMessage('bar', 2)).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: 2 })).not.toThrow();

    // Throws when message is not a below the specified minimum
    expect(() => encoder4.encodeMessage('bar', -102)).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: -102 })).toThrow();

    expect(() => encoder4.encodeMessage('bar', -100)).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: -100 })).not.toThrow();

    // Does not throw no specific encoder is defined and thus default encoder is used
    expect(() => encoder4.encodeMessage('foo1', -102)).not.toThrow();
    expect(() => encoder4.encodeMessage('foo1', 2.6)).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ foo1: -102, baz1: 'Bar1' })).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ foo1: -102, baz1: 'Bar1', barfoo: -2.6 })).not.toThrow();

    expect(() => Encoder.positiveDecimalNumberEncoder(-1)).toThrow();
    expect(() => Encoder.positiveDecimalNumberEncoder(2.3)).toThrow();

    encoders1.set('baz', Encoder.positiveDecimalNumberEncoder(3));

    const encoder5 = new Encoder(encoders1, defaultEncoder);

    // Throws when message is a negative number or other invalid type
    expect(() => encoder5.encodeMessage('baz', -2.6)).toThrow();
    expect(() => encoder5.encodeMessage('baz', -2)).toThrow();
    expect(() => encoder5.encodeMessage('baz', '-2.6')).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: -2.6 })).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: -2 })).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: '-2.6' })).toThrow();

    // Throws when message has more decimal places than intended
    expect(() => encoder5.encodeMessage('baz', 2.1234)).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.1234 })).toThrow();

    // Does not throw when message has expected number of decimal places
    expect(() => encoder5.encodeMessage('baz', 2.0)).not.toThrow();
    expect(() => encoder5.encodeMessage('baz', 2.1)).not.toThrow();
    expect(() => encoder5.encodeMessage('baz', 2.12)).not.toThrow();
    expect(() => encoder5.encodeMessage('baz', 2.13)).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.0 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.0 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.12 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.13 })).not.toThrow();

    // Does not throw when positive integers
    expect(() => encoder5.encodeMessage('baz', 2)).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2 })).not.toThrow();

    // Does not throw no specific encoder is defined and thus default encoder is used
    expect(() => encoder5.encodeMessage('foo1', -2)).not.toThrow();
    expect(() => encoder5.encodeMessage('foo1', 2.1234)).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ foo1: -2 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ foo1: 2.1234 })).not.toThrow();

    expect(() => Encoder.decimalNumberEncoder(-1000, -1)).toThrow();
    expect(() => Encoder.decimalNumberEncoder(-1000, 2.3)).toThrow();

    encoders1.set('waldo', Encoder.decimalNumberEncoder(-1000, 2));

    const encoder6 = new Encoder(encoders1, defaultEncoder);

    // Throws when message is below the intended minimum or has more decimal places than intended
    for (const v of [-1001, -999.234, 0.056, 2.123, -1002.123]) {
      expect(() => encoder6.encodeMessage('waldo', v)).toThrow();
      expect(() => encoder6.encodeMessageObject({ waldo: v })).toThrow();
    }

    // Does not throw for valid values
    for (const v of [-1000, -999, -100.1, -40.0, -5.01, -1, 0, 1, 1.2, 1.45, 100, 200.9, 300.0, 300.1, 300.2]) {
      expect(() => encoder6.encodeMessage('waldo', v)).not.toThrow();
      expect(() => encoder6.encodeMessageObject({ waldo: v })).not.toThrow();
    }
  });
});
