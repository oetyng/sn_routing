var searchIndex = JSON.parse('{\
"sn_routing":{"doc":"Peer implementation for a resilient decentralised network …","i":[[4,"Error","sn_routing","Internal error.",null,null],[13,"FailedSignature","","",0,null],[13,"CannotRoute","","",0,null],[13,"EmptyRecipientList","","",0,null],[13,"InvalidConfig","","",0,null],[13,"CannotConnectEndpoint","","",0,null],[13,"AddressNotReachable","","",0,null],[13,"Network","","",0,null],[13,"InvalidState","","",0,null],[13,"InvalidSrcLocation","","",0,null],[13,"InvalidDstLocation","","",0,null],[13,"InvalidMessage","","",0,null],[13,"InvalidSignatureShare","","",0,null],[13,"MissingSecretKeyShare","","",0,null],[13,"FailedSend","","",0,null],[13,"ConnectionClosed","","",0,null],[13,"InvalidSectionChain","","",0,null],[13,"Messaging","","",0,null],[13,"ProposalError","","",0,null],[13,"CreateError","","",0,null],[13,"ExtendProofError","","",0,null],[13,"InvalidPayload","","",0,null],[13,"TryJoinLater","","",0,null],[6,"Result","","The type returned by the sn_routing message handling …",null,null],[4,"Event","","An Event raised by a <code>Node</code> or <code>Client</code> via its event sender.",null,null],[13,"MessageReceived","","Received a message.",1,null],[12,"content","sn_routing::Event","The content of the message.",2,null],[12,"src","","The source location that sent the message.",2,null],[12,"dst","","The destination location that receives the message.",2,null],[12,"proof","","The proof if the message was set to be aggregated at …",2,null],[12,"proof_chain","","The proof chain for the message, if any.",2,null],[13,"MemberJoined","sn_routing","A new peer joined our section.",1,null],[12,"name","sn_routing::Event","Name of the node",3,null],[12,"previous_name","","Previous name before relocation or <code>None</code> if it is a new …",3,null],[12,"age","","Age of the node",3,null],[13,"MemberLeft","sn_routing","A node left our section.",1,null],[12,"name","sn_routing::Event","Name of the node",4,null],[12,"age","","Age of the node",4,null],[13,"EldersChanged","sn_routing","The set of elders in our section has changed.",1,null],[12,"prefix","sn_routing::Event","The prefix of our section.",5,null],[12,"key","","The BLS public key of our section.",5,null],[12,"sibling_key","","The BLS public key of the sibling section, if this event …",5,null],[12,"elders","","The set of elders of our section.",5,null],[12,"self_status_change","","Promoted, demoted or no change?",5,null],[13,"RelocationStarted","sn_routing","This node has started relocating to other section. Will …",1,null],[12,"previous_name","sn_routing::Event","Previous name before relocation",6,null],[13,"Relocated","sn_routing","This node has completed relocation to other section.",1,null],[12,"previous_name","sn_routing::Event","Old name before the relocation.",7,null],[12,"new_keypair","","New keypair to be used after relocation.",7,null],[13,"RestartRequired","sn_routing","Disconnected or failed to connect - restart required.",1,null],[13,"ClientMessageReceived","","Received a message from a client node.",1,null],[12,"msg","sn_routing::Event","The content of the message.",8,null],[12,"user","","The SocketAddr and PublicKey that sent the message. …",8,null],[13,"ClientLost","sn_routing","Failed in sending a message to client, or connection to …",1,null],[13,"AdultsChanged","","Notify the current list of adult nodes, in case of …",1,null],[4,"NodeElderChange","","A flag in EldersChanged event, indicating whether the …",null,null],[13,"Promoted","","The node was promoted to Elder.",9,null],[13,"Demoted","","The node was demoted to Adult.",9,null],[13,"None","","There was no change to the node.",9,null],[3,"SendStream","","Stream of outgoing messages",null,null],[3,"Config","","Routing configuration.",null,null],[12,"first","","If true, configures the node to start a new network …",10,null],[12,"keypair","","The <code>Keypair</code> of the node or <code>None</code> for randomly generated …",10,null],[12,"transport_config","","Configuration for the underlying network transport.",10,null],[3,"EventStream","","Stream of routing node events",null,null],[3,"Routing","","Interface for sending and receiving messages to and from …",null,null],[3,"SectionChain","","Chain of section BLS keys where every key is proven …",null,null],[4,"SectionChainError","","Error resulting from operations on <code>SectionChain</code>.",null,null],[13,"FailedSignature","","",11,null],[13,"KeyNotFound","","",11,null],[13,"Untrusted","","",11,null],[13,"InvalidOperation","","",11,null],[17,"FIRST_SECTION_MAX_AGE","","Defines the higher bound of this range.",null,null],[17,"FIRST_SECTION_MIN_AGE","","During the first section, nodes can start at a range of …",null,null],[17,"MIN_ADULT_AGE","","The minimum age a node becomes an adult node.",null,null],[17,"MIN_AGE","","The minimum age a node can have. The Infants will start …",null,null],[3,"TransportConfig","","QuicP2p configurations",null,null],[12,"hard_coded_contacts","","Hard Coded contacts",12,null],[12,"local_port","","Port we want to reserve for QUIC. If none supplied we\'ll …",12,null],[12,"local_ip","","IP address for the listener. If none is supplied and …",12,null],[12,"forward_port","","Specify if port forwarding via UPnP should be done or …",12,null],[12,"external_port","","External port number assigned to the socket address of …",12,null],[12,"external_ip","","External IP address of the computer on the WAN. This …",12,null],[12,"max_msg_size_allowed","","This is the maximum message size we\'ll allow the peer to …",12,null],[12,"idle_timeout_msec","","If we hear nothing from the peer in the given interval we …",12,null],[12,"keep_alive_interval_msec","","Interval to send keep-alives if we are idling so that the …",12,null],[12,"bootstrap_cache_dir","","Directory in which the bootstrap cache will be stored. If …",12,null],[12,"upnp_lease_duration","","Duration of a UPnP port mapping.",12,null],[3,"Prefix","","A section prefix, i.e. a sequence of bits specifying the …",null,null],[3,"XorName","","A 256-bit number, viewed as a point in XOR space.",null,null],[12,"0","","",13,null],[17,"XOR_NAME_LEN","","Constant byte length of <code>XorName</code>.",null,null],[17,"RECOMMENDED_SECTION_SIZE","","Recommended section size. sn_routing will keep adding …",null,null],[17,"ELDER_SIZE","","Number of elders per section.",null,null],[11,"from","","",0,[[]]],[11,"into","","",0,[[]]],[11,"to_string","","",0,[[],["string",3]]],[11,"borrow","","",0,[[]]],[11,"borrow_mut","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"vzip","","",0,[[]]],[11,"as_fail","","",0,[[],["fail",8]]],[11,"from","","",14,[[]]],[11,"into","","",14,[[]]],[11,"borrow","","",14,[[]]],[11,"borrow_mut","","",14,[[]]],[11,"try_from","","",14,[[],["result",4]]],[11,"try_into","","",14,[[],["result",4]]],[11,"type_id","","",14,[[],["typeid",3]]],[11,"vzip","","",14,[[]]],[11,"from","","",9,[[]]],[11,"into","","",9,[[]]],[11,"borrow","","",9,[[]]],[11,"borrow_mut","","",9,[[]]],[11,"try_from","","",9,[[],["result",4]]],[11,"try_into","","",9,[[],["result",4]]],[11,"type_id","","",9,[[],["typeid",3]]],[11,"vzip","","",9,[[]]],[11,"from","","",1,[[]]],[11,"into","","",1,[[]]],[11,"borrow","","",1,[[]]],[11,"borrow_mut","","",1,[[]]],[11,"try_from","","",1,[[],["result",4]]],[11,"try_into","","",1,[[],["result",4]]],[11,"type_id","","",1,[[],["typeid",3]]],[11,"vzip","","",1,[[]]],[11,"from","","",15,[[]]],[11,"into","","",15,[[]]],[11,"borrow","","",15,[[]]],[11,"borrow_mut","","",15,[[]]],[11,"try_from","","",15,[[],["result",4]]],[11,"try_into","","",15,[[],["result",4]]],[11,"type_id","","",15,[[],["typeid",3]]],[11,"vzip","","",15,[[]]],[11,"from","","",10,[[]]],[11,"into","","",10,[[]]],[11,"borrow","","",10,[[]]],[11,"borrow_mut","","",10,[[]]],[11,"try_from","","",10,[[],["result",4]]],[11,"try_into","","",10,[[],["result",4]]],[11,"type_id","","",10,[[],["typeid",3]]],[11,"vzip","","",10,[[]]],[11,"from","","",16,[[]]],[11,"into","","",16,[[]]],[11,"borrow","","",16,[[]]],[11,"borrow_mut","","",16,[[]]],[11,"try_from","","",16,[[],["result",4]]],[11,"try_into","","",16,[[],["result",4]]],[11,"type_id","","",16,[[],["typeid",3]]],[11,"vzip","","",16,[[]]],[11,"from","","",17,[[]]],[11,"into","","",17,[[]]],[11,"to_owned","","",17,[[]]],[11,"clone_into","","",17,[[]]],[11,"borrow","","",17,[[]]],[11,"borrow_mut","","",17,[[]]],[11,"try_from","","",17,[[],["result",4]]],[11,"try_into","","",17,[[],["result",4]]],[11,"type_id","","",17,[[],["typeid",3]]],[11,"vzip","","",17,[[]]],[11,"equivalent","","",17,[[],["bool",15]]],[11,"from","","",11,[[]]],[11,"into","","",11,[[]]],[11,"to_string","","",11,[[],["string",3]]],[11,"borrow","","",11,[[]]],[11,"borrow_mut","","",11,[[]]],[11,"try_from","","",11,[[],["result",4]]],[11,"try_into","","",11,[[],["result",4]]],[11,"type_id","","",11,[[],["typeid",3]]],[11,"vzip","","",11,[[]]],[11,"equivalent","","",11,[[],["bool",15]]],[11,"as_fail","","",11,[[],["fail",8]]],[11,"from","","",12,[[]]],[11,"into","","",12,[[]]],[11,"to_owned","","",12,[[]]],[11,"clone_into","","",12,[[]]],[11,"borrow","","",12,[[]]],[11,"borrow_mut","","",12,[[]]],[11,"try_from","","",12,[[],["result",4]]],[11,"try_into","","",12,[[],["result",4]]],[11,"type_id","","",12,[[],["typeid",3]]],[11,"vzip","","",12,[[]]],[11,"equivalent","","",12,[[],["bool",15]]],[11,"from","","",18,[[]]],[11,"into","","",18,[[]]],[11,"to_owned","","",18,[[]]],[11,"clone_into","","",18,[[]]],[11,"borrow","","",18,[[]]],[11,"borrow_mut","","",18,[[]]],[11,"try_from","","",18,[[],["result",4]]],[11,"try_into","","",18,[[],["result",4]]],[11,"type_id","","",18,[[],["typeid",3]]],[11,"vzip","","",18,[[]]],[11,"equivalent","","",18,[[],["bool",15]]],[11,"from","","",13,[[]]],[11,"into","","",13,[[]]],[11,"to_owned","","",13,[[]]],[11,"clone_into","","",13,[[]]],[11,"to_string","","",13,[[],["string",3]]],[11,"borrow","","",13,[[]]],[11,"borrow_mut","","",13,[[]]],[11,"try_from","","",13,[[],["result",4]]],[11,"try_into","","",13,[[],["result",4]]],[11,"type_id","","",13,[[],["typeid",3]]],[11,"vzip","","",13,[[]]],[11,"equivalent","","",13,[[],["bool",15]]],[11,"hash","","",13,[[["sha3",3]]]],[11,"write_hex","","",13,[[],[["error",3],["result",4]]]],[11,"write_hex_upper","","",13,[[],[["error",3],["result",4]]]],[11,"fmt","","",14,[[["formatter",3]],[["error",3],["result",4]]]],[11,"fmt","","",12,[[["formatter",3]],[["error",3],["result",4]]]],[11,"deserialize","","",12,[[],[["result",4],["config",3]]]],[11,"default","","",12,[[],["config",3]]],[11,"clone","","",12,[[],["config",3]]],[11,"eq","","",12,[[["config",3]],["bool",15]]],[11,"ne","","",12,[[["config",3]],["bool",15]]],[11,"clap","","",12,[[],["app",3]]],[11,"from_clap","","",12,[[["argmatches",3]],["config",3]]],[11,"serialize","","",12,[[],["result",4]]],[11,"fmt","","",13,[[["formatter",3]],[["error",3],["result",4]]]],[11,"fmt","","",18,[[["formatter",3]],[["error",3],["result",4]]]],[11,"clone","","",13,[[],["xorname",3]]],[11,"clone","","",18,[[],["prefix",3]]],[11,"from_str","","",18,[[["str",15]],[["result",4],["prefix",3]]]],[11,"deref","","",13,[[]]],[11,"as_ref","","",13,[[]]],[11,"as_ref","","",13,[[],["xorname",3]]],[11,"default","","",13,[[],["xorname",3]]],[11,"default","","",18,[[],["prefix",3]]],[11,"fmt","","",13,[[["formatter",3]],[["error",3],["result",4]]]],[11,"not","","",13,[[],["xorname",3]]],[11,"serialize","","",13,[[],["result",4]]],[11,"serialize","","",18,[[],["result",4]]],[11,"deserialize","","",18,[[],[["result",4],["prefix",3]]]],[11,"deserialize","","",13,[[],[["result",4],["xorname",3]]]],[11,"fmt","","",13,[[["formatter",3]],[["error",3],["result",4]]]],[11,"fmt","","",13,[[["formatter",3]],[["error",3],["result",4]]]],[11,"fmt","","",13,[[["formatter",3]],[["error",3],["result",4]]]],[11,"fmt","","",18,[[["formatter",3]],[["error",3],["result",4]]]],[11,"partial_cmp","","",13,[[["xorname",3]],[["option",4],["ordering",4]]]],[11,"lt","","",13,[[["xorname",3]],["bool",15]]],[11,"le","","",13,[[["xorname",3]],["bool",15]]],[11,"gt","","",13,[[["xorname",3]],["bool",15]]],[11,"ge","","",13,[[["xorname",3]],["bool",15]]],[11,"partial_cmp","","",18,[[["prefix",3]],[["option",4],["ordering",4]]]],[11,"hash","","",13,[[]]],[11,"hash","","",18,[[]]],[11,"cmp","","",13,[[["xorname",3]],["ordering",4]]],[11,"cmp","","",18,[[["prefix",3]],["ordering",4]]],[11,"eq","","",13,[[["xorname",3]],["bool",15]]],[11,"ne","","",13,[[["xorname",3]],["bool",15]]],[11,"eq","","",18,[[["prefix",3]],["bool",15]]],[11,"from","","",13,[[["publickey",4]],["xorname",3]]],[11,"drop","","",16,[[]]],[11,"from","","",0,[[["error",4]]]],[11,"from","","",0,[[["sectionchainerror",4]]]],[11,"from","","",0,[[["error",4]]]],[11,"clone","","",17,[[],["sectionchain",3]]],[11,"default","","",10,[[]]],[11,"eq","","",17,[[["sectionchain",3]],["bool",15]]],[11,"ne","","",17,[[["sectionchain",3]],["bool",15]]],[11,"eq","","",11,[[["error",4]],["bool",15]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",9,[[["formatter",3]],["result",6]]],[11,"fmt","","",1,[[["formatter",3]],["result",6]]],[11,"fmt","","",10,[[["formatter",3]],["result",6]]],[11,"fmt","","",17,[[["formatter",3]],["result",6]]],[11,"fmt","","",11,[[["formatter",3]],["result",6]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",11,[[["formatter",3]],["result",6]]],[11,"hash","","",17,[[]]],[11,"source","","",0,[[],[["option",4],["error",8]]]],[11,"serialize","","",17,[[],["result",4]]],[11,"deserialize","","",17,[[],["result",4]]],[11,"send_user_msg","","Send a message using the stream created by the initiator",14,[[["bytes",3]]]],[11,"send","","Send a wire message",14,[[["wiremsg",4]]]],[11,"finish","","Gracefully finish current stream",14,[[]]],[11,"next","","Returns next event",15,[[]]],[11,"new","","Creates new node using the given config and bootstraps it …",16,[[["config",3]]]],[11,"set_joins_allowed","","Sets the JoinsAllowed flag.",16,[[["bool",15]]]],[11,"propose_offline","","Starts a proposal that a node has gone offline. This can …",16,[[["xorname",3]]]],[11,"age","","Returns the current age of this node.",16,[[]]],[11,"public_key","","Returns the ed25519 public key of this node.",16,[[]]],[11,"keypair_as_bytes","","Returns the ed25519 keypair of this node, as bytes.",16,[[]]],[11,"sign_as_node","","Signs <code>data</code> with the ed25519 key of this node.",16,[[]]],[11,"sign_as_elder","","Signs <code>data</code> with the BLS secret key share of this node, if …",16,[[["publickey",3]]]],[11,"verify","","Verifies <code>signature</code> on <code>data</code> with the ed25519 public key of …",16,[[["signature",3]]]],[11,"name","","The name of this node.",16,[[]]],[11,"our_connection_info","","Returns connection info of this node.",16,[[],["socketaddr",4]]],[11,"section_chain","","Returns the Section Proof Chain",16,[[]]],[11,"our_prefix","","Prefix of our section",16,[[]]],[11,"matches_our_prefix","","Finds out if the given XorName matches our prefix.",16,[[["xorname",3]]]],[11,"is_elder","","Returns whether the node is Elder.",16,[[]]],[11,"our_elders","","Returns the information of all the current section elders.",16,[[]]],[11,"our_elders_sorted_by_distance_to","","Returns the elders of our section sorted by their …",16,[[["xorname",3]]]],[11,"our_adults","","Returns the information of all the current section adults.",16,[[]]],[11,"our_adults_sorted_by_distance_to","","Returns the adults of our section sorted by their …",16,[[["xorname",3]]]],[11,"our_section","","Returns the info about our section or <code>None</code> if we are not …",16,[[]]],[11,"other_sections","","Returns the info about other sections in the network …",16,[[]]],[11,"section_key","","Returns the last known public key of the section with …",16,[[["prefix",3]]]],[11,"matching_section","","Returns the info about the section matching the name.",16,[[["xorname",3]]]],[11,"send_message","","Send a message. Messages sent here, either section to …",16,[[["itinerary",3],["bytes",3],["publickey",3],["option",4]]]],[11,"public_key_set","","Returns the current BLS public key set if this node has …",16,[[]]],[11,"our_history","","Returns our section proof chain.",16,[[]]],[11,"our_index","","Returns our index in the current BLS group if this node …",16,[[]]],[11,"new","","Creates a new chain consisting of only one block.",17,[[["publickey",3]]]],[11,"insert","","Insert new key into the chain. <code>parent_key</code> must exists in …",17,[[["publickey",3],["signature",3],["publickey",3]],[["result",4],["error",4]]]],[11,"merge","","Merges two chains into one.",17,[[],[["result",4],["error",4]]]],[11,"minimize","","Creates a minimal sub-chain of <code>self</code> that contains all …",17,[[],[["result",4],["error",4]]]],[11,"truncate","","Returns a sub-chain of <code>self</code> truncated to the last <code>count</code> …",17,[[["usize",15]]]],[11,"extend","","Returns the smallest super-chain of <code>self</code> that would be …",17,[[["publickey",3]],[["result",4],["error",4]]]],[11,"keys","","Iterator over all the keys in the chain in order.",17,[[]]],[11,"root_key","","Returns the root key of this chain. This is the first key …",17,[[],["publickey",3]]],[11,"last_key","","Returns the last key of this chain.",17,[[],["publickey",3]]],[11,"prev_key","","Returns the parent key of the last key or the root key if …",17,[[],["publickey",3]]],[11,"has_key","","Returns whether <code>key</code> is present in this chain.",17,[[["publickey",3]],["bool",15]]],[11,"check_trust","","Given a collection of keys that are already trusted, …",17,[[],["bool",15]]],[11,"cmp_by_position","","Compare the two keys by their position in the chain. The …",17,[[["publickey",3]],["ordering",4]]],[11,"len","","Returns the number of blocks in the chain. This is always …",17,[[],["usize",15]]],[11,"main_branch_len","","Returns the number of block on the main branch of the …",17,[[],["usize",15]]],[11,"new","","Creates a new <code>Prefix</code> with the first <code>bit_count</code> bits of <code>name</code>…",18,[[["usize",15],["xorname",3]],["prefix",3]]],[11,"name","","Returns the name of this prefix.",18,[[],["xorname",3]]],[11,"pushed","","Returns <code>self</code> with an appended bit: <code>0</code> if <code>bit</code> is <code>false</code>, and …",18,[[["bool",15]],["prefix",3]]],[11,"popped","","Returns a prefix copying the first <code>bitcount() - 1</code> bits …",18,[[],["prefix",3]]],[11,"bit_count","","Returns the number of bits in the prefix.",18,[[],["usize",15]]],[11,"is_empty","","Returns <code>true</code> if this is the empty prefix, with no bits.",18,[[],["bool",15]]],[11,"is_compatible","","Returns <code>true</code> if <code>self</code> is a prefix of <code>other</code> or vice versa.",18,[[["prefix",3]],["bool",15]]],[11,"is_extension_of","","Returns <code>true</code> if <code>other</code> is compatible but strictly shorter …",18,[[["prefix",3]],["bool",15]]],[11,"is_neighbour","","Returns <code>true</code> if the <code>other</code> prefix differs in exactly one …",18,[[["prefix",3]],["bool",15]]],[11,"common_prefix","","Returns the number of common leading bits with the input …",18,[[["xorname",3]],["usize",15]]],[11,"matches","","Returns <code>true</code> if this is a prefix of the given <code>name</code>.",18,[[["xorname",3]],["bool",15]]],[11,"cmp_distance","","Compares the distance of <code>self</code> and <code>other</code> to <code>target</code>. …",18,[[["xorname",3],["prefix",3]],["ordering",4]]],[11,"cmp_breadth_first","","Compares the prefixes using breadth-first order. That is, …",18,[[["prefix",3]],["ordering",4]]],[11,"lower_bound","","Returns the smallest name matching the prefix",18,[[],["xorname",3]]],[11,"upper_bound","","Returns the largest name matching the prefix",18,[[],["xorname",3]]],[11,"range_inclusive","","Inclusive range from lower_bound to upper_bound",18,[[],[["rangeinclusive",3],["xorname",3]]]],[11,"is_covered_by","","Returns whether the namespace defined by <code>self</code> is covered …",18,[[],["bool",15]]],[11,"with_flipped_bit","","Returns the neighbouring prefix differing in the <code>i</code>-th bit …",18,[[["u8",15]],["prefix",3]]],[11,"substituted_in","","Returns the given <code>name</code> with first bits replaced by <code>self</code>",18,[[["xorname",3]],["xorname",3]]],[11,"sibling","","Returns the same prefix, with the last bit flipped, or …",18,[[],["prefix",3]]],[11,"ancestor","","Returns the ancestors of this prefix that has the given …",18,[[["u8",15]],["prefix",3]]],[11,"ancestors","","Returns an iterator that yields all ancestors of this …",18,[[],["ancestors",3]]],[11,"from_content","","Generate a XorName for the given content (for …",13,[[],["xorname",3]]],[11,"random","","Generate a random XorName",13,[[],["xorname",3]]],[11,"bit","","Returns <code>true</code> if the <code>i</code>-th bit is <code>1</code>.",13,[[["u8",15]],["bool",15]]],[11,"cmp_distance","","Compares the distance of the arguments to <code>self</code>. Returns …",13,[[["xorname",3]],["ordering",4]]]],"p":[[4,"Error"],[4,"Event"],[13,"MessageReceived"],[13,"MemberJoined"],[13,"MemberLeft"],[13,"EldersChanged"],[13,"RelocationStarted"],[13,"Relocated"],[13,"ClientMessageReceived"],[4,"NodeElderChange"],[3,"Config"],[4,"SectionChainError"],[3,"TransportConfig"],[3,"XorName"],[3,"SendStream"],[3,"EventStream"],[3,"Routing"],[3,"SectionChain"],[3,"Prefix"]]}\
}');
addSearchOptions(searchIndex);initSearch(searchIndex);