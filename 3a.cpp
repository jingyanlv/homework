

pragma circom 2.0.0;


const int t = 3;
const int n = 256;
const int full_rounds = 8;
const int partial_rounds = 56;
const int total_rounds = full_rounds + partial_rounds;

const MDS_MATRIX = [
    [17, 15, 41],
        [15, 41, 17],
        [41, 17, 15]
];

const ROUND_CONSTANTS = [
    [1912455270050393471, 1873706603169409404, 1427569996013340824],
        [2007713878421042692, 1468211275696464478, 1743849643760195816],
        [1269775133319906479, 1263148708066101476, 2147483647],
        [2147483647, 2147483647, 2147483647],
        [2147483647, 2147483647, 2147483647] 
];

template Sbox() {
    signal input in;
    signal output out;

    signal s1 <= = in * in;       // x^2
    signal s2 <= = s1 * s1;       // x^4
    signal s3 <= = s2 * in;       // x^5

    out <= = s3;
}


template MixLayer() {
    signal input in[t];
    signal output out[t];

   
    out[0] <= = MDS_MATRIX[0][0] * in[0] + MDS_MATRIX[0][1] * in[1] + MDS_MATRIX[0][2] * in[2];
    out[1] <= = MDS_MATRIX[1][0] * in[0] + MDS_MATRIX[1][1] * in[1] + MDS_MATRIX[1][2] * in[2];
    out[2] <= = MDS_MATRIX[2][0] * in[0] + MDS_MATRIX[2][1] * in[1] + MDS_MATRIX[2][2] * in[2];
}


template Poseidon2Round(round_idx) {
    signal input state[t];
    signal output next_state[t];


    signal added_state[t];
    for (var i = 0; i < t; i++) {
        added_state[i] <= = state[i] + ROUND_CONSTANTS[round_idx][i];
    }

  
    signal sbox_state[t];
    component sboxes[t];
    for (var i = 0; i < t; i++) {
        sboxes[i] = Sbox();
        sboxes[i].in <= = added_state[i];
        sbox_state[i] <= = sboxes[i].out;
    }


    component mix = MixLayer();
    for (var i = 0; i < t; i++) {
        mix.in[i] <= = sbox_state[i];
    }
    for (var i = 0; i < t; i++) {
        next_state[i] <= = mix.out[i];
    }
}

template Poseidon2PartialRound(round_idx) {
    signal input state[t];
    signal output next_state[t];

 
    signal added_state[t];
    for (var i = 0; i < t; i++) {
        added_state[i] <= = state[i] + ROUND_CONSTANTS[round_idx][i];
    }

 
    component sbox = Sbox();
    sbox.in <= = added_state[0];
    signal sbox_state[t];
    sbox_state[0] <= = sbox.out;
    for (var i = 1; i < t; i++) {
        sbox_state[i] <= = added_state[i];
    }

 
    component mix = MixLayer();
    for (var i = 0; i < t; i++) {
        mix.in[i] <= = sbox_state[i];
    }
    for (var i = 0; i < t; i++) {
        next_state[i] <= = mix.out[i];
    }
}


template Poseidon2Permutation() {
    signal input state[t];
    signal output out[t];

    signal round_state[total_rounds + 1][t];

   
    for (var i = 0; i < t; i++) {
        round_state[0][i] <= = state[i];
    }

    var round_idx = 0;

   
    for (var r = 0; r < full_rounds / 2; r++) {
        component round = Poseidon2Round(round_idx);
        round_idx++;
        for (var i = 0; i < t; i++) {
            round.in[i] <= = round_state[r][i];
        }
        for (var i = 0; i < t; i++) {
            round_state[r + 1][i] <= = round.out[i];
        }
    }

    for (var r = full_rounds / 2; r < full_rounds / 2 + partial_rounds; r++) {
        component round = Poseidon2PartialRound(round_idx);
        round_idx++;
        for (var i = 0; i < t; i++) {
            round.in[i] <= = round_state[r][i];
        }
        for (var i = 0; i < t; i++) {
            round_state[r + 1][i] <= = round.out[i];
        }
    }

  
    for (var r = full_rounds / 2 + partial_rounds; r < total_rounds; r++) {
        component round = Poseidon2Round(round_idx);
        round_idx++;
        for (var i = 0; i < t; i++) {
            round.in[i] <= = round_state[r][i];
        }
        for (var i = 0; i < t; i++) {
            round_state[r + 1][i] <= = round.out[i];
        }
    }


    for (var i = 0; i < t; i++) {
        out[i] <= = round_state[total_rounds][i];
    }
}


template Poseidon2Hash() {
    signal input inputs[t - 1];  
    signal output hash;


    signal state[t];
    for (var i = 0; i < t - 1; i++) {
        state[i] <= = inputs[i];
    }
    state[t - 1] <= = 0;  

    component permutation = Poseidon2Permutation();
    for (var i = 0; i < t; i++) {
        permutation.in[i] <= = state[i];
    }

  
    hash <= = permutation.out[0];
}


template Main() {
   
    signal private input preimage[2];
    signal output hash;
    component hasher = Poseidon2Hash();
    hasher.inputs[0] <= = preimage[0];
    hasher.inputs[1] <= = preimage[1];
    hash <= = hasher.hash;
}

component main = Main();