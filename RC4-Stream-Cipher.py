import random
def Swap(a, b): return b,a

def encrypt(Key, P):
    S=[i for i in range(8)]
    T=[Key[i%len(Key)] for i in range(8)]
    print("Initialized S: ", S)
    print("Initialized T: ", T)
    
    j=0
    for i in range (8):
        j = (j + S[i] + T[i]) % 8
        S[i],S[j]=Swap(S[i],S[j]); 

    print("\n")    
    print("S before Iterations: ",S)
    print("\n")

    i= 0
    j= 0
    K=[0 for i in range(len(P))]
    for i in range (len(P)):
        i = (i + 1) % 8;
        j = (j + S[i]) % 8;
        S[i],S[j]=Swap(S[i], S[j]);
        t = (S[i] + S[j]) % 8;
        K[(i-1)%8] = S[t]; 
        print(f"Iteration {i+1}: ",S)

    Encrypt = [K[i] ^ P[i]  for i in range(len(P))]
    return Encrypt

if __name__=='__main__':
    print("==================================================")
    print("Simplified Version of RC4 Stream Cipher ")
    print("--------------------------------------------------")
    Key=[1,2,3,6]#[random.randrange(0,8) for i in range(4)]
    print("Randomly Generated Key: ",Key)

    P=[1,2,2,2]
    print("Plain Text: ",P)

    Encrypted=encrypt(Key,P)
    print("Encrypted Text: ",Encrypted)
    print("--------------------------------------------------")
    print("Decrypted Text: ",encrypt(Key,Encrypted))
    print("==================================================")