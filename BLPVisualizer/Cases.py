import sys
from BLP import BLP

def setup_initial_state():
    """Returns a fresh BLP instance loaded with the base assignment criteria."""
    blp = BLP()
    print("\n[System] Initializing Default State...")
    blp.add_subject("alice", "S", "U")
    blp.add_subject("bob", "C", "C")
    blp.add_subject("eve", "U", "U")
    
    blp.add_object("pub.txt", "U")
    blp.add_object("emails.txt", "C")
    blp.add_object("username.txt", "S")
    blp.add_object("password.txt", "TS")
    return blp

# Add each case here
TEST_CASES = {
    # Case 1: Alice reads emails.txt
    # Alice starts at U, emails.txt is C. Since C <= Alice's max (S), her level is raised to C and read is allow.
    1: [("read", "alice", "emails.txt")],

    # Case 2: Alice reads password.txt
    # Alice's max level is S, but password.txt is TS. Since TS > Alice's max, read is deny (no read up).
    2: [("read", "alice", "password.txt")],

    # Case 3: Eve reads pub.txt
    # Eve's current level is U and pub.txt is U. Since U <= U, read is allow (same level).
    3: [("read", "eve", "pub.txt")],

    # Case 4: Eve reads emails.txt
    # Eve's max level is U, but emails.txt is C. Since C > Eve's max, read is deny (no read up).
    4: [("read", "eve", "emails.txt")],

    # Case 5: Bob reads password.txt
    # Bob's max level is C, but password.txt is TS. Since TS > Bob's max, read is deny (no read up).
    5: [("read", "bob", "password.txt")],

    # Case 6: Alice reads emails.txt then writes to pub.txt
    # Alice reads emails.txt (allow, level raised to C). Writing to pub.txt is deny because
    # Alice's current level (C) is higher than pub.txt (U), violating the no write down rule.
    6: [("read", "alice", "emails.txt"), ("write", "alice", "pub.txt")],

    # Case 7: Alice reads emails.txt then writes to password.txt
    # Alice reads emails.txt (allow, level raised to C). Writing to password.txt is allow because
    # Alice's current level (C) is lower than password.txt (TS), complying with the no write down rule.
    7: [("read", "alice", "emails.txt"), ("write", "alice", "password.txt")],

    # Case 8: Alice reads emails.txt, writes to emails.txt, reads username.txt, writes to emails.txt
    # Alice reads emails.txt (allow, level raised to C), writes to emails.txt (allow, C==C).
    # Alice reads username.txt (allow, level raised to S). Final write to emails.txt is deny
    # because Alice's current level (S) is now higher than emails.txt (C), violating no write down.
    8: [
        ("read",  "alice", "emails.txt"),
        ("write", "alice", "emails.txt"),
        ("read",  "alice", "username.txt"),
        ("write", "alice", "emails.txt"),
    ],

    # Case 9: Alice reads emails.txt, writes to username.txt, reads password.txt, writes to emails.txt
    # Alice reads emails.txt (allow, level raised to C). Write to username.txt is allow (C <= S, writing up).
    # Read password.txt is deny (TS > Alice's max S, level stays C). Write to emails.txt is allow (C <= C).
    9: [
        ("read",  "alice", "emails.txt"),
        ("write", "alice", "username.txt"),
        ("read",  "alice", "password.txt"),
        ("write", "alice", "emails.txt"),
    ],

    # Case 10: Alice reads pub.txt, writes to emails.txt, Bob reads emails.txt
    # Alice reads pub.txt (allow, U==U, no level change). Write to emails.txt is allow (U <= C).
    # Bob reads emails.txt (allow, Bob's current level C == emails.txt C).
    10: [
        ("read",  "alice", "pub.txt"),
        ("write", "alice", "emails.txt"),
        ("read",  "bob",   "emails.txt"),
    ],

    # Case 11: Alice reads pub.txt, writes to username.txt, Bob reads username.txt
    # Alice reads pub.txt (allow, no level change). Write to username.txt is allow (U <= S).
    # Bob reads username.txt is deny because username.txt (S) exceeds Bob's max level (C).
    11: [
        ("read",  "alice", "pub.txt"),
        ("write", "alice", "username.txt"),
        ("read",  "bob",   "username.txt"),
    ],

    # Case 12: Alice reads pub.txt, writes to password.txt, Bob reads password.txt
    # Alice reads pub.txt (allow, no level change). Write to password.txt is allow (U <= TS).
    # Bob reads password.txt is deny because password.txt (TS) exceeds Bob's max level (C).
    12: [
        ("read",  "alice", "pub.txt"),
        ("write", "alice", "password.txt"),
        ("read",  "bob",   "password.txt"),
    ],

    # Case 13: Alice reads pub.txt, writes to emails.txt, Eve reads emails.txt
    # Alice reads pub.txt (allow, no level change). Write to emails.txt is allow (U <= C).
    # Eve reads emails.txt is deny because emails.txt (C) exceeds Eve's max level (U).
    13: [
        ("read",  "alice", "pub.txt"),
        ("write", "alice", "emails.txt"),
        ("read",  "eve",   "emails.txt"),
    ],

    # Case 14: Alice reads emails.txt, writes to pub.txt, Eve reads pub.txt
    # Alice reads emails.txt (allow, level raised to C). Write to pub.txt is deny because
    # Alice's current level (C) > pub.txt (U), violating no write down.
    # Eve reads pub.txt is allow since pub.txt (U) == Eve's current level (U).
    14: [
        ("read",  "alice", "emails.txt"),
        ("write", "alice", "pub.txt"),
        ("read",  "eve",   "pub.txt"),
    ],

    # Case 15: Alice sets her level to S then reads username.txt
    # Alice raises her current level to S (within her max of S). Reading username.txt
    # is then allow because username.txt (S) <= Alice's current level (S).
    15: [
        ("set_level", "alice", "S"),
        ("read",      "alice", "username.txt"),
    ],

    # Case 16: Alice reads emails.txt, tries to set level to U, writes to pub.txt, Eve reads pub.txt
    # Alice reads emails.txt (allow, level raised to C). The set_level to U is deny because BLP
    # prevents lowering current level (no write down enforcement). Alice's level stays C,
    # so writing to pub.txt is also deny (C > U). Eve's read of pub.txt is allow (U == U).
    16: [
        ("read",      "alice", "emails.txt"),
        ("set_level", "alice", "U"),
        ("write",     "alice", "pub.txt"),
        ("read",      "eve",   "pub.txt"),
    ],

    # Case 17: Alice reads username.txt, tries to set level to C, writes to emails.txt, Eve reads emails.txt
    # Alice reads username.txt (allow, level raised to S). Set_level to C is deny (cannot lower from S).
    # Alice's level stays at S, so writing to emails.txt is deny (S > C, no write down).
    # Eve reads emails.txt is deny because emails.txt (C) exceeds Eve's max level (U).
    17: [
        ("read",      "alice", "username.txt"),
        ("set_level", "alice", "C"),
        ("write",     "alice", "emails.txt"),
        ("read",      "eve",   "emails.txt"),
    ],

    # Case 18: Eve reads pub.txt then reads emails.txt
    # Eve reads pub.txt (allow, U == U). Eve then tries to read emails.txt, which is deny
    # because emails.txt (C) exceeds Eve's max level (U) — no read up.
    18: [
        ("read", "eve", "pub.txt"),
        ("read", "eve", "emails.txt"),
    ],
}

def execute_commands(blp, commands):
    for cmd in commands:
        action = cmd[0]
        if action == "read":
            blp.read(cmd[1], cmd[2])
        elif action == "write":
            blp.write(cmd[1], cmd[2])
        elif action == "set_level":
            blp.set_level(cmd[1], cmd[2])
        elif action == "validate":
            blp.validate_levels(cmd[1], cmd[2])

def main():
    print("========================================")
    print(" Bell-LaPadula (BLP) Simulator CLI      ")
    print("========================================")

    while True:
        print("\nOptions:")
        print("  [1-18] Run a specific test case (1 to 18)")
        print("  [A] Run all test cases sequentially")
        print("  [Q] Quit")
        choice = input("\nEnter choice: ").strip().upper()

        if choice == 'Q':
            print("Exiting simulator. Goodbye!")
            sys.exit(0)

        elif choice == 'A':
            for case_num in sorted(TEST_CASES.keys()):
                print(f"\n================ CASE #{case_num} ================")

                blp = setup_initial_state() 
                execute_commands(blp, TEST_CASES[case_num])
                blp.display_state()

        elif choice.isdigit() and int(choice) in TEST_CASES:
            case_num = int(choice)
            print(f"\n================ CASE #{case_num} ================")
            blp = setup_initial_state()
            execute_commands(blp, TEST_CASES[case_num])
            blp.display_state()

        else:
            print("Invalid input. Please enter a valid case number, 'A', or 'Q'.")

if __name__ == "__main__":
    main()
