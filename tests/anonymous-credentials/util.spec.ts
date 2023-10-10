import { flattenPredicatesInSpec } from '../../src';

describe('check flattening', () => {
  it('flattenPredicatesInSpec', () => {
    const nestedObj = {
      a: {
        b: {
          c: [
            { x: 1, y: 2 },
            { x: 3, y: 4 }
          ],
          d: [
            { x: 5, y: 6 },
            { x: 7, y: 8 }
          ]
        }
      }
    };

    expect(flattenPredicatesInSpec(nestedObj)).toEqual([
      ['a.b.c', 'a.b.d'],
      [
        [
          { x: 1, y: 2 },
          { x: 3, y: 4 }
        ],
        [
          { x: 5, y: 6 },
          { x: 7, y: 8 }
        ]
      ]
    ]);

    const nestedObj1 = {
      a: {
        b: {
          c: [
            { x: 1, y: 2 },
            { x: 3, y: 4 }
          ],
          d: [
            { x: 5, y: 6 },
            { x: 7, y: 8 }
          ]
        },
        e: [
          { x: 1, y: 2 },
          { x: 3, y: 4 }
        ]
      }
    };

    expect(flattenPredicatesInSpec(nestedObj1)).toEqual([
      ['a.b.c', 'a.b.d', 'a.e'],
      [
        [
          { x: 1, y: 2 },
          { x: 3, y: 4 }
        ],
        [
          { x: 5, y: 6 },
          { x: 7, y: 8 }
        ],
        [
          { x: 1, y: 2 },
          { x: 3, y: 4 }
        ],
      ]
    ]);
  });
});
